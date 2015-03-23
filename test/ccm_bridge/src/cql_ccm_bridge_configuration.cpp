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

#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include "logger.hpp"
#include "cql_ccm_bridge_configuration.hpp"

using namespace std;

namespace cql {
const std::string cql_ccm_bridge_configuration_t::DEFAULT_CASSANDRA_VERSION = "2.1.3";
const std::string cql_ccm_bridge_configuration_t::DEFAULT_CASSANDRA_VERSION_ONE_DOWNGRADE = "1.2.19";
#ifndef DISABLE_LIBSSH2
const std::string cql_ccm_bridge_configuration_t::DEFAULT_IP_PREFIX = "192.168.33.1";
#else
const std::string cql_ccm_bridge_configuration_t::DEFAULT_IP_PREFIX = "127.0.0.";
#endif
const std::string cql_ccm_bridge_configuration_t::DEFAULT_SSH_HOST = "192.168.33.11";
const int cql_ccm_bridge_configuration_t::DEFAULT_SSH_PORT = 22;
const std::string cql_ccm_bridge_configuration_t::DEFAULT_SSH_USERNAME = "vagrant";
const std::string cql_ccm_bridge_configuration_t::DEFAULT_SSH_PASSWORD = "vagrant";
const std::string cql_ccm_bridge_configuration_t::DEFAULT_COMPRESSION = "NONE";
const std::string cql_ccm_bridge_configuration_t::DEFAULT_DEPLOYMENT_TYPE = "LOCAL";

cql_ccm_bridge_configuration_t::cql_ccm_bridge_configuration_t()
  : ip_prefix_(DEFAULT_IP_PREFIX)
  , cassandra_version_(DEFAULT_CASSANDRA_VERSION)
  , cassandra_version_one_downgrade_(DEFAULT_CASSANDRA_VERSION_ONE_DOWNGRADE)
  , ssh_host_(DEFAULT_SSH_HOST)  // Vagrant VM
  , ssh_port_(DEFAULT_SSH_PORT)
  , ssh_username_(DEFAULT_SSH_USERNAME)
  , ssh_password_(DEFAULT_SSH_PASSWORD)
  , compression_(DEFAULT_COMPRESSION)
  , deployment_type_(DEFAULT_DEPLOYMENT_TYPE) {
}

const string& cql_ccm_bridge_configuration_t::ip_prefix() const {
  return ip_prefix_;
}

const string& cql_ccm_bridge_configuration_t::cassandara_version() const {
  return cassandra_version_;
}

const string& cql_ccm_bridge_configuration_t::cassandara_version_one_downgrade() const {
  return cassandra_version_one_downgrade_;
}

const string& cql_ccm_bridge_configuration_t::ssh_host() const {
  return ssh_host_;
}

short cql_ccm_bridge_configuration_t::ssh_port() const {
  return ssh_port_;
}

const string& cql_ccm_bridge_configuration_t::ssh_username() const {
  return ssh_username_;
}

const string& cql_ccm_bridge_configuration_t::ssh_password() const {
  return ssh_password_;
}

std::string cql_ccm_bridge_configuration_t::compression() const {
  return compression_;
}

const string& cql_ccm_bridge_configuration_t::deployment_type() const {
  return deployment_type_;
}

bool cql_ccm_bridge_configuration_t::is_empty(string line) {
  boost::trim(line);
  return line.empty();
}

bool cql_ccm_bridge_configuration_t::is_comment(string line) {
  boost::trim(line);
  return boost::starts_with(line, "#");
}

const std::string cql_ccm_bridge_configuration_t::to_compression(const string& value) const {
  if (value == "none") {
    return "NONE";
  } else if (value == "lz4") {
    return "LZ4";
  } else if (value == "snappy") {
    return "SNAPPY";
  } else {
    CQL_LOG(warning) << "Invalid COMPRESSION value: " << value;
    return DEFAULT_COMPRESSION;
  }
}

const std::string cql_ccm_bridge_configuration_t::to_deployment_type(const string& value) const {
  if (value == "local") {
    return "LOCAL";
#ifndef DISABLE_LIBSSH2
  } else if (value == "ssh") {
    return "SSH";
#endif
  } else {
    CQL_LOG(warning) << "Invalid DEPLOYMENT_TYPE value: " << value;
    return DEFAULT_DEPLOYMENT_TYPE;
  }
}

cql_ccm_bridge_configuration_t::settings_t cql_ccm_bridge_configuration_t::get_settings(
    const string& file_name) {
  settings_t settings;

  string line;
  ifstream settings_file(file_name.c_str(), ios_base::in);

  if (!settings_file) {
    CQL_LOG(error) << "Cannot open configuration file: " << file_name;
    return settings;
  }

  while (getline(settings_file, line)) {
    if (is_comment(line) || is_empty(line))
      continue;

    add_setting(settings, line);
  }

  return settings;
}

void cql_ccm_bridge_configuration_t::add_setting(settings_t& settings, string line) {
  boost::trim(line);

  size_t eq_pos = line.find('=');
  if (eq_pos != string::npos) {
    string key = line.substr(0, eq_pos);
    string value = line.substr(eq_pos + 1, line.size());

    boost::trim(key);
    boost::to_lower(key);
    boost::trim(value);

    if (!key.empty() && !value.empty()) {
      settings[key] = value;
      if (key != "ssh_password") {
        CQL_LOG(info) << "Configuration key: " << key << " equals value: " << value;
      }
      return;
    }
  }

  CQL_LOG(warning) << "Invalid configuration entry: " << line;
}

void cql_ccm_bridge_configuration_t::apply_settings(const settings_t& settings) {
  for (settings_t::const_iterator it = settings.begin(); it != settings.end(); ++it) {
    apply_setting(/* key: */it->first, /* value: */it->second);
  }
}

void cql_ccm_bridge_configuration_t::apply_setting(const string& key, const string& value) {
  if (key == "ssh_username") {
    ssh_username_ = value;
  } else if (key == "ssh_password") {
    ssh_password_ = value;
  } else if (key == "ssh_port") {
    try {
      ssh_port_ = boost::lexical_cast<short>(value);
    } catch (boost::bad_lexical_cast&) {
      CQL_LOG(error) << "Invalid SSH_PORT value: " << value;
      ssh_port_ = DEFAULT_SSH_PORT;
    }
  } else if (key == "ssh_host") {
    ssh_host_ = value;
  } else if (key == "ip_prefix") {
    ip_prefix_ = value;
  } else if (key == "cassandra_version") {
    cassandra_version_ = value;
  }  else if (key == "cassandra_version_one_downgrade") {
    cassandra_version_one_downgrade_ = value;
  } else if (key == "compression") {
    compression_ = to_compression(boost::to_lower_copy(value));
  }
  else if (key == "deployment_type") {
    deployment_type_ = to_deployment_type(boost::to_lower_copy(value));
  } else {
    CQL_LOG(warning) << "Unknown configuration option: " << key << " with value " << value;
  }
}

void cql_ccm_bridge_configuration_t::read_configuration(const std::string& file_name) {
  settings_t settings = get_settings(file_name);
  apply_settings(settings);
}

// Singleton implementation by static variable
const cql_ccm_bridge_configuration_t& get_ccm_bridge_configuration(const std::string& filename) {
  static cql_ccm_bridge_configuration_t config;
  static bool initialized = false;

  if (!initialized) {
    config.read_configuration(filename);
    initialized = true;
  }

  return config;
}
}
