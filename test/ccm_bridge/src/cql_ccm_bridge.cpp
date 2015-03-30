/*
 Copyright (c) 2014-2015 DataStax

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <boost/thread.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>

#ifndef DISABLE_LIBSSH2
#  include <libssh2.h>
#endif

#ifdef WIN32
#	 define popen _popen
#	 define pclose _pclose
#  include <winsock2.h>
#elif UNIX
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#else
#  error "Unsupported system"
#endif

#include "logger.hpp"
#include "cql_ccm_bridge.hpp"
#include "safe_advance.hpp"

using namespace std;

#ifndef DISABLE_LIBSSH2
const int SSH_STDOUT = 0;
const int SSH_STDERR = 1;
#endif

namespace cql {

#ifndef DISABLE_LIBSSH2
struct cql_ccm_bridge_t::ssh_internals {
 public:
  ssh_internals()
    : _session(0)
    ,  _channel(0) {
  }
  LIBSSH2_SESSION* _session;
  LIBSSH2_CHANNEL* _channel;
};
#endif

const string cql_ccm_bridge_t::CCM_COMMAND = "ccm";
int64_t cql_ccm_bridge_t::local_exit_status_ = 0;
std::stringstream cql_ccm_bridge_t::local_command_stdout_;
std::stringstream cql_ccm_bridge_t::local_command_stderr_;

#ifndef DISABLE_LIBSSH2
cql_ccm_bridge_t::cql_ccm_bridge_t(const cql_ccm_bridge_configuration_t& settings)
  : ip_prefix_(settings.ip_prefix())
  , cassandra_version_(settings.cassandara_version())
  , socket_(-1)
  , ssh_internals_(new ssh_internals())
  , is_local_(true) {
  if (settings.deployment_type() == "SSH") {
    is_local_ = false;
    initialize_socket_library();

    try {
      // initialize libssh2 - not thread safe
      if (0 != libssh2_init(0))
        throw cql_ccm_bridge_exception_t("cannot initialize libssh2 library");

      try {
        start_connection(settings);

        try {
          start_ssh_connection(settings);
        } catch (cql_ccm_bridge_exception_t&) {
          close_socket();
          throw;
        }
      } catch (cql_ccm_bridge_exception_t&) {
        libssh2_exit();
        throw;
      }
    } catch (cql_ccm_bridge_exception_t&) {
      finalize_socket_library();
      throw;
    }
    initialize_environment();
  }
}

cql_ccm_bridge_t::~cql_ccm_bridge_t() {
  if (!is_local_) {
    libssh2_channel_free(ssh_internals_->_channel);
    close_ssh_session();

    close_socket();
    libssh2_exit();
    finalize_socket_library();
  }
}

void cql_ccm_bridge_t::start_connection(const cql_ccm_bridge_configuration_t& settings) {
  socket_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (socket_ == -1)
    throw cql_ccm_bridge_exception_t("cannot create socket");

  sockaddr_in socket_address;

  socket_address.sin_family = AF_INET;
  socket_address.sin_port = htons(settings.ssh_port());
  socket_address.sin_addr.s_addr = inet_addr(settings.ssh_host().c_str());

  int result = connect(socket_, reinterpret_cast<sockaddr *>(&socket_address),
                       sizeof(socket_address));
  if (result == -1) {
    close_socket();
    throw cql_ccm_bridge_exception_t("cannot connect to remote host");
  }
}

void cql_ccm_bridge_t::close_ssh_session() {
  libssh2_session_disconnect(ssh_internals_->_session, "Requested by user.");
  libssh2_session_free(ssh_internals_->_session);
}

void cql_ccm_bridge_t::start_ssh_connection(const cql_ccm_bridge_configuration_t& settings) {
  ssh_internals_->_session = libssh2_session_init();
  if (!ssh_internals_->_session)
    throw cql_ccm_bridge_exception_t("cannot create ssh session");

  try {
    if (libssh2_session_handshake(ssh_internals_->_session, socket_))
      throw cql_ccm_bridge_exception_t("ssh session handshake failed");

    // get authentication modes supported by server
    char* auth_methods = libssh2_userauth_list(ssh_internals_->_session,
                                               settings.ssh_username().c_str(),
                                               settings.ssh_username().size());

    if (strstr(auth_methods, "password") == NULL)
      throw cql_ccm_bridge_exception_t("server doesn't support authentication by password");

    // try to login using username and password
    int auth_result = libssh2_userauth_password(ssh_internals_->_session,
                                                settings.ssh_username().c_str(),
                                                settings.ssh_password().c_str());

    if (auth_result != 0)
      throw cql_ccm_bridge_exception_t("invalid password or user");

    if (!(ssh_internals_->_channel = libssh2_channel_open_session(ssh_internals_->_session)))
      throw cql_ccm_bridge_exception_t("cannot open ssh session");

    try {

      if (libssh2_channel_request_pty(ssh_internals_->_channel, "vanilla"))
        throw cql_ccm_bridge_exception_t("pty requests failed");

      if (libssh2_channel_shell(ssh_internals_->_channel))
        throw cql_ccm_bridge_exception_t("cannot open shell");

      //TODO: Copy SSL files to remote connection for CCM to enable SSL with Cassandra instances (or use keytool to simply generate the files remotely)
    } catch (cql_ccm_bridge_exception_t&) {
      // calls channel_close
      libssh2_channel_free(ssh_internals_->_channel);
    }
  } catch (cql_ccm_bridge_exception_t&) {
    close_ssh_session();
    throw;
  }
}

void cql_ccm_bridge_t::close_socket() {
#ifdef WIN32
  closesocket(socket_);
#else
  close(socket_);
#endif
  socket_ = -1;
}

void cql_ccm_bridge_t::initialize_socket_library() {
#ifdef WIN32
  WSADATA wsadata;
  if(0 != WSAStartup(MAKEWORD(2,0), &wsadata)) {
    throw cql_ccm_bridge_exception_t("cannot initialize windows sockets");
  }
#endif
}

void cql_ccm_bridge_t::finalize_socket_library() {
#ifdef WIN32
  WSACleanup();
#endif
}

void cql_ccm_bridge_t::initialize_environment() {
  wait_for_shell_prompth();

  // clear buffers
  esc_remover_stdout_.clear_buffer();
  esc_remover_stdout_.clear_buffer();

  // disable terminal echo
  execute_command("stty", "-echo");
}

void cql_ccm_bridge_t::wait_for_shell_prompth() {
  const char SHELL_PROMPTH_CHARACTER = '$';

  while (!esc_remover_stdout_.ends_with_character(SHELL_PROMPTH_CHARACTER)) {
    if (libssh2_channel_eof(ssh_internals_->_channel)) {
      throw cql_ccm_bridge_exception_t("connection closed by remote host");
    }

    terminal_read_stream(esc_remover_stdout_, SSH_STDOUT);
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  }
}

string cql_ccm_bridge_t::terminal_read_stdout() {
  return terminal_read(esc_remover_stdout_, SSH_STDOUT);
}

string cql_ccm_bridge_t::terminal_read_stderr() {
  return terminal_read(esc_remover_stderr_, SSH_STDERR);
}

string cql_ccm_bridge_t::terminal_read(cql_escape_sequences_remover_t& buffer, int stream) {
  terminal_read_stream(buffer, stream);

  if (buffer.data_available()) {
    return buffer.get_buffer_contents();
  }

  return string();
}

void cql_ccm_bridge_t::terminal_read_stream(cql_escape_sequences_remover_t& buffer, int stream) {
  char buf[128];

  while (true) {
    // disable blocking
    libssh2_session_set_blocking(ssh_internals_->_session, 0);

    ssize_t readed = libssh2_channel_read_ex(ssh_internals_->_channel, stream, buf, sizeof(buf));

    // return if no data to read
    if (readed == LIBSSH2_ERROR_EAGAIN || readed == 0) {
      return;
    }

    // some error occurred
    if (readed < 0) {
      throw cql_ccm_bridge_exception_t("error during reading from socket");
    }

    buffer.push_character_range(buf, buf + readed);
  }
}

void cql_ccm_bridge_t::terminal_write(const string& command) {
  // enable blocking
  libssh2_channel_set_blocking(ssh_internals_->_channel, 1);
  libssh2_channel_write(ssh_internals_->_channel, command.c_str(), command.size());
}
#else

cql_ccm_bridge_t::cql_ccm_bridge_t(const cql_ccm_bridge_configuration_t& settings)
  : ip_prefix_(settings.ip_prefix())
  , cassandra_version_(settings.cassandara_version())
  , is_local_(true) {}

cql_ccm_bridge_t::~cql_ccm_bridge_t() {}
#endif

void cql_ccm_bridge_t::execute_ccm_command(const string& ccm_args) {
  const int RETRY_TIMES = 2;

  for (int retry = 0; retry < RETRY_TIMES; retry++) {
    CQL_LOG(info) << "CCM " << ccm_args;
    string result = execute_command(CCM_COMMAND, ccm_args);

    if (boost::algorithm::contains(result, "[Errno")) {
      CQL_LOG(error) << "CCM ERROR: " << result;

      if (boost::algorithm::contains(result, "[Errno 17")) {
        execute_ccm_and_print("remove test");
      }
    } else
      return;
  }
  throw cql_ccm_bridge_exception_t("ccm operation failed");
}

#if UV_VERSION_MAJOR == 0
void cql_ccm_bridge_t::execute_local_command_finish(uv_process_t *process, int exit_status, int term_signal) {
#else
void cql_ccm_bridge_t::execute_local_command_finish(uv_process_t *process, int64_t exit_status, int term_signal) {
#endif
  local_exit_status_ = exit_status;
  uv_close((uv_handle_t*) process, NULL);
}

#if UV_VERSION_MAJOR == 0
uv_buf_t cql_ccm_bridge_t::allocate_command_output_buffer(uv_handle_t *handle, size_t length) {
  return uv_buf_init(new char[length], length);
#else
void cql_ccm_bridge_t::allocate_command_output_buffer(uv_handle_t *handle, size_t length, uv_buf_t *buffer) {
  buffer->base = new char[length];
  buffer->len = length;
#endif
}

#if UV_VERSION_MAJOR == 0
void cql_ccm_bridge_t::read_stdout(uv_stream_t *stream, ssize_t bytes_read, uv_buf_t buffer) {
  // Ensure the buffer can be read
  if (bytes_read > 0 && bytes_read < buffer.len) {
    local_command_stdout_ << std::string(buffer.base, bytes_read);
  }

  if (buffer.base) {
    delete []buffer.base;
  }
#else
void cql_ccm_bridge_t::read_stdout(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer) {
  // Ensure the buffer can be read
  if (bytes_read > 0 && bytes_read < buffer->len) {
    local_command_stdout_ << std::string(buffer->base, bytes_read);
  }

  if (buffer->base) {
    delete []buffer->base;
  }
#endif
}

#if UV_VERSION_MAJOR == 0
void cql_ccm_bridge_t::read_stderr(uv_stream_t *stream, ssize_t bytes_read, uv_buf_t buffer) {
  // Ensure the buffer can be read
  if (bytes_read > 0 && bytes_read < buffer.len) {
    local_command_stderr_ << std::string(buffer.base, bytes_read);
  }

  if (buffer.base) {
    delete []buffer.base;
  }
#else
void cql_ccm_bridge_t::read_stderr(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer) {
  // Ensure the buffer can be read
  if (bytes_read > 0 && bytes_read < buffer->len) {
    local_command_stderr_ << std::string(buffer->base, bytes_read);
  }

  if (buffer->base) {
    delete []buffer->base;
  }
#endif
}

std::string cql_ccm_bridge_t::execute_local_command(const std::string& command, const std::string& args) const {
  // Split the argument into tokens
  std::stringstream args_stream(args);
  std::vector<std::string> tokens;
  std::string token;
  while (std::getline(args_stream, token, ' ')) {
    tokens.push_back(token);
  }

  // Create the option arguments from the tokens (very limiting for arguments)
#ifdef _WIN32
  char **options_args = new char*[5 + tokens.size()];
  options_args[0] = "cmd.exe";
  options_args[1] = "/C";
  unsigned int n = 2;
#else
  char **options_args = new char*[2 + tokens.size()];
  unsigned int n = 0;
#endif
  options_args[n++] = const_cast<char *>(command.c_str());
  for (std::vector<std::string>::iterator token_iterator = tokens.begin() ; token_iterator != tokens.end(); ++token_iterator) {
    options_args[n++] = const_cast<char *>((*token_iterator).c_str());
  }
  options_args[n] = NULL;

  // Create the base options for the process
  uv_process_options_t options = { 0 };
  options.exit_cb = cql_ccm_bridge_t::execute_local_command_finish;
  options.env = NULL;
  options.file = options_args[0];
  options.args = options_args;

  // Initialize the pipes for stdout and stderr
  uv_loop_t *process_loop = uv_default_loop();
  uv_pipe_t stdout_pipe;
  uv_pipe_t stderr_pipe;
  uv_pipe_init(process_loop, &stdout_pipe, 0);
  uv_pipe_init(process_loop, &stderr_pipe, 0);

  // Initialize the pipe streams and add to the process options
  options.stdio_count = 3;
  uv_stdio_container_t child_stdio[3];
  child_stdio[0].flags = UV_IGNORE;
  child_stdio[1].flags = (uv_stdio_flags) (UV_CREATE_PIPE | UV_READABLE_PIPE);
  child_stdio[1].data.stream = reinterpret_cast<uv_stream_t *>(&stdout_pipe);
  child_stdio[2].flags = (uv_stdio_flags) (UV_CREATE_PIPE | UV_READABLE_PIPE);
  child_stdio[2].data.stream = reinterpret_cast<uv_stream_t *>(&stderr_pipe);
  options.stdio = child_stdio;

  // Create and spawn the process for the command execution
  uv_process_t process;
#if UV_VERSION_MAJOR == 0
  if (int error_code = uv_spawn(process_loop, &process, options)) {
    return std::string(uv_strerror(uv_last_error(process_loop)));
#else
  if (int error_code = uv_spawn(process_loop, &process, &options)) {
    return std::string(uv_strerror(error_code));
#endif
  }
  uv_read_start(reinterpret_cast<uv_stream_t *>(&stdout_pipe), cql_ccm_bridge_t::allocate_command_output_buffer, cql_ccm_bridge_t::read_stdout);
  uv_read_start(reinterpret_cast<uv_stream_t*>(&stderr_pipe), cql_ccm_bridge_t::allocate_command_output_buffer, cql_ccm_bridge_t::read_stderr);
  uv_run(process_loop, UV_RUN_DEFAULT);

  // Perform cleanup
#if UV_VERSION_MAJOR == 0
  uv_loop_delete(process_loop);
#endif
  delete []options_args;

  // Return the output results
  std::stringstream results;
  results << local_command_stdout_.str() << local_command_stderr_.str();
  return results.str();
}

string cql_ccm_bridge_t::execute_command(const std::string& command, const std::string& args) {
  if (is_local_) {
    return execute_local_command(command, args);
  }

#ifndef DISABLE_LIBSSH2
  terminal_write(command + " " + args);
  terminal_write("\n");

  wait_for_shell_prompth();

  string result = "";
  result += terminal_read_stdout();
  result += terminal_read_stderr();
  return result;
#endif
}

void cql_ccm_bridge_t::execute_ccm_and_print(const std::string& ccm_args) {
  CQL_LOG(info) << "CCM " << ccm_args;
  string result = execute_command(CCM_COMMAND, ccm_args);

  if (boost::algorithm::contains(result, "[Errno")) {
    CQL_LOG(error) << "CCM ERROR: " << result;
  } else {
    CQL_LOG(info) << "CCM RESULT: " << result;
  }
}

CassVersion cql_ccm_bridge_t::get_cassandra_version() {
  //Convert the cassandra_version value into the CassVersion structure
  CassVersion version;
  sscanf(cassandra_version_.c_str(), "%hu.%hu.%hu-%s", &version.major, &version.minor, &version.patch, version.extra);
  return version;
}


CassVersion cql_ccm_bridge_t::get_cassandra_version(int node) {
  //Get the version string from CCM
  std::string version_string = execute_command(CCM_COMMAND, boost::str(boost::format("node%1% version") % node));
  size_t prefix_index = version_string.find("ReleaseVersion: ");
  if (prefix_index != std::string::npos) {
    version_string.replace(0, 16, "");
  }

  //Convert the version string into the CassVersion structure
  CassVersion version;
  sscanf(version_string.c_str(), "%hu.%hu.%hu-%s", &version.major, &version.minor, &version.patch, version.extra);
  return version;
}

void cql_ccm_bridge_t::update_config(const std::string& name, const std::string& value) {
  execute_ccm_command(boost::str(boost::format("updateconf %1%:%2%") % name % value));
}

void cql_ccm_bridge_t::start() {
  execute_ccm_command("start --wait-other-notice --wait-for-binary-proto");
}

void cql_ccm_bridge_t::start(int node) {
  execute_ccm_command(boost::str(boost::format("node%1% start --wait-other-notice --wait-for-binary-proto") % node));
}

void cql_ccm_bridge_t::start(int node, const std::string& option) {
  execute_ccm_command(boost::str(boost::format("node%1% start --wait-other-notice --wait-for-binary-proto --jvm_arg=%2%") % node % option));
}

void cql_ccm_bridge_t::stop() {
  execute_ccm_command("stop");
}

void cql_ccm_bridge_t::stop(int node) {
  execute_ccm_command(boost::str(boost::format("node%1% stop") % node));
}

void cql_ccm_bridge_t::kill() {
  execute_ccm_command("stop --not-gently");
}

void cql_ccm_bridge_t::kill(int node) {
  execute_ccm_command(boost::str(boost::format("node%1% stop --not-gently") % node));
}

void cql_ccm_bridge_t::binary(int node, bool enable) {
  if (enable) {
    execute_ccm_command(boost::str(boost::format("node%1% nodetool enablebinary") % node));
  } else {
    execute_ccm_command(boost::str(boost::format("node%1% nodetool disablebinary") % node));
  }
}

void cql_ccm_bridge_t::gossip(int node, bool enable) {
  if (enable) {
    execute_ccm_command(boost::str(boost::format("node%1% nodetool enablegossip") % node));
  } else {
    execute_ccm_command(boost::str(boost::format("node%1% nodetool disablegossip") % node));
  }
}

void cql_ccm_bridge_t::remove() {
  stop();
  execute_ccm_command("remove");
}

void cql_ccm_bridge_t::ring(int node) {
  execute_ccm_command(boost::str(boost::format("node%1% ring") % node));
}

void cql_ccm_bridge_t::populate(int n) {
  execute_ccm_command(boost::str(boost::format("populate -n %1% -i %2%") % n % ip_prefix_));
}

void cql_ccm_bridge_t::add_node(int node) {
  execute_ccm_command(boost::str(boost::format("add node%1% -i %2%%3% -j %4% -b") % node % ip_prefix_ % node % (7000 + 100 * node)));
}

void cql_ccm_bridge_t::add_node(int node, const std::string& dc) {
  execute_ccm_command(boost::str(boost::format("add node%1% -i %2%%3% -j %4% -b -d %5%") % node % ip_prefix_ % node % (7000 + 100 * node) % dc));
}

void cql_ccm_bridge_t::bootstrap(int node) {
  add_node(node);
  start(node);
}

void cql_ccm_bridge_t::bootstrap(int node, const std::string& dc) {
  add_node(node, dc);
  start(node);
}

void cql_ccm_bridge_t::decommission(int node) {
  execute_ccm_command(boost::str(boost::format("node%1% decommission") % node));
}

CassVersion cql_ccm_bridge_t::version() {
  return get_cassandra_version();
}

CassVersion cql_ccm_bridge_t::version(int node) {
  return get_cassandra_version(node);
}

boost::shared_ptr<cql_ccm_bridge_t> cql_ccm_bridge_t::create(
    const cql_ccm_bridge_configuration_t& settings, const std::string& name,
    bool is_version_one /* = false */, bool is_ssl /* = false */,
    bool is_client_authentication /* = false */) {
  boost::shared_ptr<cql_ccm_bridge_t> bridge(new cql_ccm_bridge_t(settings));

  bridge->execute_ccm_command(boost::str(boost::format("remove %1%") % name));

  std::string ccm_command = boost::str(boost::format("create %1% -b -i %2% -v %3%") % name % settings.ip_prefix()
                                       % (is_version_one ? settings.cassandara_version_one_downgrade() : settings.cassandara_version()));
  if (is_ssl) {
    ccm_command += " --ssl=ssl";
    if (is_client_authentication) {
      ccm_command += " --require_client_auth";
    }
  }

  bridge->execute_ccm_command(ccm_command);

  return bridge;
}

boost::shared_ptr<cql_ccm_bridge_t> cql_ccm_bridge_t::create_and_start(
    const cql_ccm_bridge_configuration_t& settings, const std::string& name,
    unsigned nodes_count_dc1, unsigned nodes_count_dc2 /* = 0 */, bool is_ssl /* = false */,
    bool is_client_authentication /* = false */) {
  boost::shared_ptr<cql_ccm_bridge_t> bridge(new cql_ccm_bridge_t(settings));

  bridge->execute_ccm_command(boost::str(boost::format("remove %1%") % name));

  std::string ccm_command = boost::str(
      boost::format("create %1% -n %2%:%3% -i %4% -b -v %5%") % name % nodes_count_dc1
      % nodes_count_dc2 % settings.ip_prefix() % settings.cassandara_version());

  if (is_ssl) {
    ccm_command += " --ssl=ssl";
    if (is_client_authentication) {
      ccm_command += " --require_client_auth";
    }
  }

  bridge->execute_ccm_command(ccm_command);

  bridge->start();
  return bridge;
}
}
