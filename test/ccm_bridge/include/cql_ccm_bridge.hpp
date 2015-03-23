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

#ifndef CQL_CCM_BRIDGE_H_
#define CQL_CCM_BRIDGE_H_

#include <exception>
#include <deque>
#include <sstream>
#include <string.h>

#include <boost/smart_ptr.hpp>
#include <boost/noncopyable.hpp>

#include <uv.h>

#include "cql_ccm_bridge_configuration.hpp"
#include "cql_escape_sequences_remover.hpp"

/**
 * Cassandra release version number
 */
struct CassVersion {
  /**
   * Major portion of version number
   */
  unsigned short major;
  /**
   * Minor portion of version number
   */
  unsigned short minor;
  /**
   * Patch portion of version number
   */
  unsigned short patch;
  /**
   * Extra portion of version number
   */
  char extra[64];

  /**
   * Initializing constructor for structure
   */
  CassVersion() {
    major = 0;
    minor = 0;
    patch = 0;
    memset(extra, '\0', sizeof(extra));
  };
};

namespace cql {
class cql_ccm_bridge_t : public boost::noncopyable {
 public:
  cql_ccm_bridge_t(const cql_ccm_bridge_configuration_t& settings);
  ~cql_ccm_bridge_t();

  // Executes command on remote host
  // Returns command stdout and stderr followed by
  // shell prompth.
  std::string execute_command(const std::string& command, const std::string& args);

  void update_config(const std::string& name, const std::string& value);

  void start();
  void start(int node);
  void start(int node, const std::string& option);
  void stop();
  void stop(int node);
  void kill();
  void kill(int node);
  void binary(int node, bool enable);
  void gossip(int node, bool enable);

  void remove();
  void ring(int node);

  void populate(int n);

  void add_node(int node);
  void add_node(int node, const std::string& dc);
  void bootstrap(int node);
  void bootstrap(int node, const std::string& dc);

  void decommission(int node);

  /**
   * Get the configuration version of Cassandra
   *
   * @return CassVersion defining version information from configuration
   */
  CassVersion version();
  /**
   * Get the version of a Cassandra node
   *
   * @param node Node to get version from
   * @return CassVersion defining version information for Cassandra node
   */
  CassVersion version(int node);

  //TODO: Allow CCM create to keep instances if settings are the same
  static boost::shared_ptr<cql_ccm_bridge_t> create(const cql_ccm_bridge_configuration_t& settings,
                                                    const std::string& name, bool is_version_one = false,
                                                    bool is_ssl = false, bool is_client_authentication = false);

  static boost::shared_ptr<cql_ccm_bridge_t> create_and_start(
      const cql_ccm_bridge_configuration_t& settings, const std::string& name,
      unsigned nodes_count_dc1, unsigned nodes_count_dc2 = 0, bool is_ssl = false,
      bool is_client_authentication = false);

 private:
  /* CCM functionality */
  static const std::string CCM_COMMAND;
  const std::string ip_prefix_;
  const std::string cassandra_version_;
  /**
   * Flag to determine if local commands should be executed
   */
  bool is_local_;
  /**
   * Exit code/status for local execution
   */
  static int64_t local_exit_status_;
  /**
   * Standard out for local command execution
   */
  static std::stringstream local_command_stdout_;
  /**
   * Standard error for local command execution
   */
  static std::stringstream local_command_stderr_;

  /**
   * [libuv callback] Handle uv_spawn process ending/termination
   *
   * @param process Process executed
   * @param exit_status Exit code/status
   * @param term_signal Signal (if issued) for terminating process
   */
#if UV_VERSION_MAJOR == 0
  static void execute_local_command_finish(uv_process_t *process, int exit_status, int term_signal);
#else
  static void execute_local_command_finish(uv_process_t *process, int64_t exit_status, int term_signal);
#endif
  /**
   * [libuv callback] Allocate memory for stdin/stderr buffer
   *
   * @param handle Handle for process pipe
   * @param length Length to allocate for buffer
   * @param buffer Buffer to allocate memory for (if uv.major > 0)
   * @return Allocated memory buffer (uv.major == 0)
   */
#if UV_VERSION_MAJOR == 0
  static uv_buf_t allocate_command_output_buffer(uv_handle_t *handle, size_t length);
#else
  static void allocate_command_output_buffer(uv_handle_t *handle, size_t length, uv_buf_t *buffer);
#endif
  /**
   * [libuv callback] Handle stdout output for local command execution
   *
   * @param stream Incoming stdout stream
   * @param btyes_read Number of bytes read from the stream
   * @param buffer Buffer containing the output from the execution
   */
#if UV_VERSION_MAJOR == 0
  static void read_stdout(uv_stream_t *stream, ssize_t bytes_read, uv_buf_t buffer);
#else
  static void read_stdout(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer);
#endif
  /**
   * [libuv callback] Handle stderr output for local command execution
   *
   * @param stream Incoming stderr stream
   * @param btyes_read Number of bytes read from the stream
   * @param buffer Buffer containing the output from the execution
   */
#if UV_VERSION_MAJOR == 0
  static void read_stderr(uv_stream_t *stream, ssize_t bytes_read, uv_buf_t buffer);
#else
  static void read_stderr(uv_stream_t *stream, ssize_t bytes_read, const uv_buf_t *buffer);
#endif
  /**
   * Execute a local command
   *
   * @param command Command to execute
   * @param args Argument for the command; these arguments get parsed into an
   *             array delimited by <space>
   * @return stdin and stdout for the executing command
   */
  std::string execute_local_command(const std::string& command, const std::string& args) const;

  void execute_ccm_command(const std::string& ccm_args);
  void execute_ccm_and_print(const std::string& ccm_args);

  /**
   * Get the version information from the configuration file and parse the
   * data into a CassVersion structure
   *
   * @return CassVersion defining version information for CCM configuration
   */
  CassVersion get_cassandra_version();
  /**
   * Execute CCM command to get version information from a node and parse the
   * data into a CassVersion structure
   *
   * @param node Node to get version information from
   * @return CassVersion defining version information for Cassandra node
   */
  CassVersion get_cassandra_version(int node);

#ifndef DISABLE_LIBSSH2
  /* SSH connection functionality */

  void initialize_environment();
  void wait_for_shell_prompth();

  std::string terminal_read_stdout();
  std::string terminal_read_stderr();
  std::string terminal_read(cql_escape_sequences_remover_t& buffer, int stream);
  void terminal_read_stream(cql_escape_sequences_remover_t& buffer, int stream);

  void terminal_write(const std::string& command);

  void initialize_socket_library();
  void finalize_socket_library();

  void start_connection(const cql_ccm_bridge_configuration_t& settings);
  void close_socket();
  void start_ssh_connection(const cql_ccm_bridge_configuration_t& settings);
  void close_ssh_session();

  cql_escape_sequences_remover_t esc_remover_stdout_;
  cql_escape_sequences_remover_t esc_remover_stderr_;

  int socket_;
  struct ssh_internals;
  boost::scoped_ptr<ssh_internals> ssh_internals_;
#endif
};

class cql_ccm_bridge_exception_t : public std::exception {
 public:
  cql_ccm_bridge_exception_t(const char* message)
      : message_(message) {
  }

  virtual const char* what() const throw () {
    return message_;
  }
 private:
  const char* const message_;
};
}

#endif // CQL_CCM_BRIDGE_H_
