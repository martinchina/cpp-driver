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

#ifndef __CASSANDRA_H_INCLUDED__
#define __CASSANDRA_H_INCLUDED__

#include <stddef.h>

#if !defined(CASS_STATIC)
#  if defined(_WIN32)
#    if defined(CASS_BUILDING)
#      define CASS_EXPORT __declspec(dllexport)
#    else
#      define CASS_EXPORT __declspec(dllexport)
#    endif
#  elif (defined(__SUNPRO_C)  || defined(__SUNPRO_CC)) && !defined(CASS_STATIC)
#    define CASS_EXPORT __global
#  elif (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER)
#    define CASS_EXPORT __attribute__ ((visibility("default")))
#  endif
#else
#define CASS_EXPORT
#endif

/**
 * @file include/cassandra.h
 *
 * C/C++ driver for Apache Cassandra. Uses the Cassandra Query Language versions 3
 * over the Cassandra Binary Protocol (versions 1 or 2).
 */

#define CASS_VERSION_MAJOR 1
#define CASS_VERSION_MINOR 0
#define CASS_VERSION_PATCH 1
#define CASS_VERSION_SUFFIX ""

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { cass_false = 0, cass_true = 1 } cass_bool_t;

typedef float cass_float_t;
typedef double cass_double_t;

#if defined(__INT8_TYPE__) && defined(__UINT8_TYPE__)
typedef __INT8_TYPE__ cass_int8_t;
typedef __UINT8_TYPE__ cass_uint8_t;
#elif defined(__INT8_TYPE__)
typedef __INT8_TYPE__ cass_int8_t;
typedef unsigned __INT8_TYPE__ cass_uint8_t;
#else
typedef char cass_int8_t;
typedef unsigned char cass_uint8_t;
#endif

#if defined(__INT16_TYPE__) && defined(__UINT16_TYPE__)
typedef __INT16_TYPE__ cass_int16_t;
typedef __UINT16_TYPE__ cass_uint16_t;
#elif defined(__INT16_TYPE__)
typedef __INT16_TYPE__ cass_int16_t;
typedef unsigned __INT16_TYPE__ cass_uint16_t;
#else
typedef short cass_int16_t;
typedef unsigned short cass_uint16_t;
#endif

#if defined(__INT32_TYPE__) && defined(__UINT32_TYPE__)
typedef __INT32_TYPE__ cass_int32_t;
typedef __UINT32_TYPE__ cass_uint32_t;
#elif defined(__INT32_TYPE__)
typedef __INT32_TYPE__ cass_int32_t;
typedef unsigned __INT32_TYPE__ cass_uint32_t;
#else
typedef int cass_int32_t;
typedef unsigned int cass_uint32_t;
#endif

#if defined(__INT64_TYPE__) && defined(__UINT64_TYPE__)
typedef __INT64_TYPE__ cass_int64_t;
typedef __UINT64_TYPE__ cass_uint64_t;
#elif defined(__INT64_TYPE__)
typedef __INT64_TYPE__ cass_int64_t;
typedef unsigned __INT64_TYPE__ cass_uint64_t;
#elif defined(__GNUC__)
typedef long long int cass_int64_t;
typedef unsigned long long int cass_uint64_t;
#else
typedef long long cass_int64_t;
typedef unsigned long long cass_uint64_t;
#endif

typedef cass_uint8_t cass_byte_t;
typedef cass_uint64_t cass_duration_t;

/**
 * The size of a IPv4 address
 */
#define CASS_INET_V4_LENGTH 4

/**
 * The size of a IPv6 address
 */
#define CASS_INET_V6_LENGTH 16

/**
 * The size of an inet string including a null terminator.
 */
#define CASS_INET_STRING_LENGTH 46

/**
 * @struct CassInet
 *
 * IP address for either IPv4 or IPv6.
 */
typedef struct CassInet_ {
  cass_uint8_t address[CASS_INET_V6_LENGTH];
  cass_uint8_t address_length;
} CassInet;

/**
 * The size of a hexidecimal UUID string including a null terminator.
 */
#define CASS_UUID_STRING_LENGTH 37

/**
 * @struct CassUuid
 *
 * Type 1 (time-based) or type 4 (random) UUID.
 */
typedef struct CassUuid_ {
  cass_uint64_t time_and_version;
  cass_uint64_t clock_seq_and_node;
} CassUuid;

/**
 * @struct CassCluster
 *
 * A cluster object describes the configuration of the Cassandra cluster and is used
 * to construct a session instance. Unlike other DataStax drivers the cluster object
 * does not maintain the control connection.
 */
typedef struct CassCluster_ CassCluster;

/**
 * @struct CassSession
 *
 * A session object is used to execute queries and maintains cluster state through
 * the control connection. The control connection is used to auto-discover nodes and
 * monitor cluster changes (topology and schema). Each session also maintains multiple
 * pools of connections to cluster nodes which are used to query the cluster.
 *
 * Instances of the session object are thread-safe to execute queries.
 */
typedef struct CassSession_ CassSession;

/**
 * @struct CassStatement
 *
 * A statement object is an executable query. It represents either a regular
 * (adhoc) statment or a prepared statement. It maitains the queries' parameter
 * values along with query options (consistency level, paging state, etc.)
 *
 * Note: Parameters for regular queries are not supported by the binary protocol
 * version 1.
 */
typedef struct CassStatement_ CassStatement;

/**
 * @struct CassBatch
 *
 * A group of statements that are executed as a single batch.
 *
 * Note: Batches are not supported by the binary protocol version 1.
 */
typedef struct CassBatch_ CassBatch;

/**
 * @struct CassFuture
 *
 * The future result of an operation.
 *
 * It can represent a result if the operation completed successfully or an
 * error if the operation failed. It can be waited on, polled or a callback
 * can be attached.
 *
 */
typedef struct CassFuture_ CassFuture;

/**
 * @struct CassPrepared
 *
 * A statement that has been prepared cluster-side (It has been pre-parsed
 * and cached).
 *
 * A prepared statement is read-only and it is thread-safe to concurrently
 * bind new statements.
 */
typedef struct CassPrepared_ CassPrepared;

/**
 * @struct CassResult
 *
 * The result of a query.
 *
 * A result object is read-only and is thread-safe to read or iterate over
 * concurrently.
 */
typedef struct CassResult_ CassResult;

/**
 * @struct CassIterator
 *
 * An object used to iterate over a group of rows, columns or collection values.
 */
typedef struct CassIterator_ CassIterator;

/**
 * @struct CassRow
 *
 * A collection of column values.
 */
typedef struct CassRow_ CassRow;

/**
 * @struct CassValue
 *
 * A single primitive value or a collection of values.
 */
typedef struct CassValue_ CassValue;

/**
 * @struct CassCollection
 *
 *  A collection of primitive values.
 */
typedef struct CassCollection_ CassCollection;

/**
 * @struct CassSsl
 *
 * Describes the SSL configuration of a cluster.
 */
typedef struct CassSsl_ CassSsl;

/**
 * @struct CassSchema
 *
 * A snapshot of the cluster's schema metadata.
 */
typedef struct CassSchema_ CassSchema;

/**
 * @struct CassSchemaMeta
 *
 * Table/Column schema metdata.
 */
typedef struct CassSchemaMeta_ CassSchemaMeta;

/**
 * @struct CassSchemaMetaField
 *
 * Key/Value metadata field for a keyspace, table, or column.
 */
typedef struct CassSchemaMetaField_ CassSchemaMetaField;

/**
 * @struct CassUuidGen
 *
 * A UUID generator object.
 *
 * Instances of the UUID generator object are thread-safe to generate UUIDs.
 */
typedef struct CassUuidGen_ CassUuidGen;

/**
 * @struct CassMetric
 *
 * A snapshot of the session's performance/diagnostic metrics.
 */
typedef struct CassMetrics_ {
  struct {
    cass_uint64_t min; /**< Minimum in microseconds */
    cass_uint64_t max; /**< Maximum in microseconds */
    cass_uint64_t mean; /**< Mean in microseconds */
    cass_uint64_t stddev; /**< Standard deviation in microseconds */
    cass_uint64_t median; /**< Median in microseconds */
    cass_uint64_t percentile_75th; /**< 75th percentile in microseconds */
    cass_uint64_t percentile_95th; /**< 95th percentile in microseconds */
    cass_uint64_t percentile_98th; /**< 98th percentile in microseconds */
    cass_uint64_t percentile_99th; /**< 99the percentile in microseconds */
    cass_uint64_t percentile_999th; /**< 99.9th percentile in microseconds */
    cass_double_t mean_rate; /**<  Mean rate in requests per second*/
    cass_double_t one_minute_rate; /**< 1 minute rate in requests per second */
    cass_double_t five_minute_rate; /**<  5 minute rate in requests per second*/
    cass_double_t fifteen_minute_rate; /**< 15 minute rate in requests per second*/
  } requests;

  struct {
    cass_uint64_t total_connections; /**< The total number of connections */
    cass_uint64_t available_connections; /**< The number of connections available to take requests */
    cass_uint64_t exceeded_pending_requests_water_mark; /**< Occurrences when requests exceeded a pool's water mark */
    cass_uint64_t exceeded_write_bytes_water_mark; /**< Occurrences when number of bytes exceeded a connection's water mark */
  } stats;

  struct {
    cass_uint64_t connection_timeouts; /**< Occurrences of a connection timeout */
    cass_uint64_t pending_request_timeouts; /** Occurrences of requests that timed out waiting for a connection */
    cass_uint64_t request_timeouts; /** Occurrences of requests that timed out waiting for a request to finish */
  } errors;

} CassMetrics;

typedef enum CassConsistency_ {
  CASS_CONSISTENCY_ANY          = 0x0000,
  CASS_CONSISTENCY_ONE          = 0x0001,
  CASS_CONSISTENCY_TWO          = 0x0002,
  CASS_CONSISTENCY_THREE        = 0x0003,
  CASS_CONSISTENCY_QUORUM       = 0x0004,
  CASS_CONSISTENCY_ALL          = 0x0005,
  CASS_CONSISTENCY_LOCAL_QUORUM = 0x0006,
  CASS_CONSISTENCY_EACH_QUORUM  = 0x0007,
  CASS_CONSISTENCY_SERIAL       = 0x0008,
  CASS_CONSISTENCY_LOCAL_SERIAL = 0x0009,
  CASS_CONSISTENCY_LOCAL_ONE    = 0x000A
} CassConsistency;

typedef enum CassValueType_ {
  CASS_VALUE_TYPE_UNKNOWN   = 0xFFFF,
  CASS_VALUE_TYPE_CUSTOM    = 0x0000,
  CASS_VALUE_TYPE_ASCII     = 0x0001,
  CASS_VALUE_TYPE_BIGINT    = 0x0002,
  CASS_VALUE_TYPE_BLOB      = 0x0003,
  CASS_VALUE_TYPE_BOOLEAN   = 0x0004,
  CASS_VALUE_TYPE_COUNTER   = 0x0005,
  CASS_VALUE_TYPE_DECIMAL   = 0x0006,
  CASS_VALUE_TYPE_DOUBLE    = 0x0007,
  CASS_VALUE_TYPE_FLOAT     = 0x0008,
  CASS_VALUE_TYPE_INT       = 0x0009,
  CASS_VALUE_TYPE_TEXT      = 0x000A,
  CASS_VALUE_TYPE_TIMESTAMP = 0x000B,
  CASS_VALUE_TYPE_UUID      = 0x000C,
  CASS_VALUE_TYPE_VARCHAR   = 0x000D,
  CASS_VALUE_TYPE_VARINT    = 0x000E,
  CASS_VALUE_TYPE_TIMEUUID  = 0x000F,
  CASS_VALUE_TYPE_INET      = 0x0010,
  CASS_VALUE_TYPE_LIST      = 0x0020,
  CASS_VALUE_TYPE_MAP       = 0x0021,
  CASS_VALUE_TYPE_SET       = 0x0022
} CassValueType;

typedef enum CassCollectionType_ {
  CASS_COLLECTION_TYPE_LIST = CASS_VALUE_TYPE_LIST,
  CASS_COLLECTION_TYPE_MAP = CASS_VALUE_TYPE_MAP,
  CASS_COLLECTION_TYPE_SET = CASS_VALUE_TYPE_SET
} CassCollectionType;

typedef enum CassBatchType_ {
  CASS_BATCH_TYPE_LOGGED   = 0,
  CASS_BATCH_TYPE_UNLOGGED = 1,
  CASS_BATCH_TYPE_COUNTER  = 2
} CassBatchType;

typedef enum CassIteratorType_ {
  CASS_ITERATOR_TYPE_RESULT,
  CASS_ITERATOR_TYPE_ROW,
  CASS_ITERATOR_TYPE_COLLECTION,
  CASS_ITERATOR_TYPE_MAP,
  CASS_ITERATOR_TYPE_SCHEMA_META,
  CASS_ITERATOR_TYPE_SCHEMA_META_FIELD
} CassIteratorType;

typedef enum CassSchemaMetaType_ {
  CASS_SCHEMA_META_TYPE_KEYSPACE,
  CASS_SCHEMA_META_TYPE_TABLE,
  CASS_SCHEMA_META_TYPE_COLUMN
} CassSchemaMetaType;

#define CASS_LOG_LEVEL_MAP(XX) \
  XX(CASS_LOG_DISABLED, "") \
  XX(CASS_LOG_CRITICAL, "CRITICAL") \
  XX(CASS_LOG_ERROR, "ERROR") \
  XX(CASS_LOG_WARN, "WARN") \
  XX(CASS_LOG_INFO, "INFO") \
  XX(CASS_LOG_DEBUG, "DEBUG") \
  XX(CASS_LOG_TRACE, "TRACE")

typedef enum CassLogLevel_ {
#define XX_LOG(log_level, _) log_level,
  CASS_LOG_LEVEL_MAP(XX_LOG)
#undef XX_LOG
  /* @cond IGNORE */
  CASS_LOG_LAST_ENTRY
  /* @endcond */
} CassLogLevel;

typedef enum CassSslVerifyFlags {
  CASS_SSL_VERIFY_NONE          = 0,
  CASS_SSL_VERIFY_PEER_CERT     = 1,
  CASS_SSL_VERIFY_PEER_IDENTITY = 2
} CassSslVerifyFlags;

typedef enum  CassErrorSource_ {
  CASS_ERROR_SOURCE_NONE,
  CASS_ERROR_SOURCE_LIB,
  CASS_ERROR_SOURCE_SERVER,
  CASS_ERROR_SOURCE_SSL,
  CASS_ERROR_SOURCE_COMPRESSION
} CassErrorSource;

#define CASS_ERROR_MAP(XX) \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_BAD_PARAMS, 1, "Bad parameters") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NO_STREAMS, 2, "No streams available") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNABLE_TO_INIT, 3, "Unable to initialize") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_MESSAGE_ENCODE, 4, "Unable to encode message") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_HOST_RESOLUTION, 5, "Unable to resolve host") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNEXPECTED_RESPONSE, 6, "Unexpected response from server") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_REQUEST_QUEUE_FULL, 7, "The request queue is full") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NO_AVAILABLE_IO_THREAD, 8, "No available IO threads") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_WRITE_ERROR, 9, "Write error") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NO_HOSTS_AVAILABLE, 10, "No hosts available") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_INDEX_OUT_OF_BOUNDS, 11, "Index out of bounds") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_INVALID_ITEM_COUNT, 12, "Invalid item count") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_INVALID_VALUE_TYPE, 13, "Invalid value type") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_REQUEST_TIMED_OUT, 14, "Request timed out") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNABLE_TO_SET_KEYSPACE, 15, "Unable to set keyspace") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_CALLBACK_ALREADY_SET, 16, "Callback already set") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_INVALID_STATEMENT_TYPE, 17, "Invalid statement type") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NAME_DOES_NOT_EXIST, 18, "No value or column for name") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNABLE_TO_DETERMINE_PROTOCOL, 19, "Unable to find supported protocol version") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NULL_VALUE, 20, "NULL value specified") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_NOT_IMPLEMENTED, 21, "Not implemented") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNABLE_TO_CONNECT, 22, "Unable to connect") \
  XX(CASS_ERROR_SOURCE_LIB, CASS_ERROR_LIB_UNABLE_TO_CLOSE, 23, "Unable to close") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_SERVER_ERROR, 0x0000, "Server error") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_PROTOCOL_ERROR, 0x000A, "Protocol error") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_BAD_CREDENTIALS, 0x0100, "Bad credentials") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_UNAVAILABLE, 0x1000, "Unavailable") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_OVERLOADED, 0x1001, "Overloaded") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_IS_BOOTSTRAPPING, 0x1002, "Is bootstrapping") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_TRUNCATE_ERROR, 0x1003, "Truncate error") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_WRITE_TIMEOUT, 0x1100, "Write timeout") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_READ_TIMEOUT, 0x1200, "Read timeout") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_SYNTAX_ERROR, 0x2000, "Syntax error") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_UNAUTHORIZED, 0x2100, "Unauthorized") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_INVALID_QUERY, 0x2200, "Invalid query") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_CONFIG_ERROR, 0x2300, "Configuration error") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_ALREADY_EXISTS, 0x2400, "Already exists") \
  XX(CASS_ERROR_SOURCE_SERVER, CASS_ERROR_SERVER_UNPREPARED, 0x2500, "Unprepared") \
  XX(CASS_ERROR_SOURCE_SSL, CASS_ERROR_SSL_INVALID_CERT, 1, "Unable to load certificate") \
  XX(CASS_ERROR_SOURCE_SSL, CASS_ERROR_SSL_INVALID_PRIVATE_KEY, 2, "Unable to load private key") \
  XX(CASS_ERROR_SOURCE_SSL, CASS_ERROR_SSL_NO_PEER_CERT, 3, "No peer certificate")  \
  XX(CASS_ERROR_SOURCE_SSL, CASS_ERROR_SSL_INVALID_PEER_CERT, 4, "Invalid peer certificate") \
  XX(CASS_ERROR_SOURCE_SSL, CASS_ERROR_SSL_IDENTITY_MISMATCH, 5, "Certificate does not match host or IP address")

#define CASS_ERROR(source, code) ((source << 24) | code)

typedef enum CassError_ {
  CASS_OK = 0,
#define XX_ERROR(source, name, code, _) name = CASS_ERROR(source, code),
  CASS_ERROR_MAP(XX_ERROR)
#undef XX_ERROR
  /* @cond IGNORE */
  CASS_ERROR_LAST_ENTRY
  /* @endcond*/
} CassError;

/**
 * A callback that's notified when the future is set.
 */
typedef void (*CassFutureCallback)(CassFuture* future,
                                   void* data);

/**
 * Maximum size of a log message
 */
#define CASS_LOG_MAX_MESSAGE_SIZE 256

/**
 * A log message.
 */
typedef struct CassLogMessage_ {
  cass_uint64_t time_ms;
  CassLogLevel severity;
  const char* file;
  int line;
  const char* function;
  char message[CASS_LOG_MAX_MESSAGE_SIZE];
} CassLogMessage;

/**
 * A callback that's used to handle logging.
 */
typedef void (*CassLogCallback)(const CassLogMessage* message,
                                void* data);

/***********************************************************************************
 *
 * Cluster
 *
 ***********************************************************************************/

/**
 * Creates a new cluster.
 *
 * @public @memberof CassCluster
 *
 * @return Returns a cluster that must be freed.
 *
 * @see cass_cluster_free()
 */
CASS_EXPORT CassCluster*
cass_cluster_new();

/**
 * Frees a cluster instance.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 */
CASS_EXPORT void
cass_cluster_free(CassCluster* cluster);

/**
 * Sets/Appends contact points. This *MUST* be set. The first call sets
 * the contact points and any subsequent calls appends additional contact
 * points. Passing an empty string will clear the contact points. White space
 * is striped from the contact points.
 *
 * Examples: "127.0.0.1" "127.0.0.1,127.0.0.2", "server1.domain.com"
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] contact_points A comma delimited list of addresses or
 * names. An empty string will clear the contact points.
 * The string is copied into the cluster configuration; the memory pointed
 * to by this parameter can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_contact_points(CassCluster* cluster,
                                const char* contact_points);

/**
  * @see cass_cluster_set_contact_points()
  */
CASS_EXPORT CassError
cass_cluster_set_contact_points_n(CassCluster* cluster,
                                  const char* contact_points,
                                  size_t contact_points_length);

/**
 * Sets the port.
 *
 * Default: 9042
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] port
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_port(CassCluster* cluster,
                      int port);

/**
 * Sets the SSL context and enables SSL.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] ssl
 *
 * @see cass_ssl_new()
 */
CASS_EXPORT void
cass_cluster_set_ssl(CassCluster* cluster,
                     CassSsl* ssl);

/**
 * Sets the protocol version. This will automatically downgrade if to
 * protocol version 1.
 *
 * Default: 2
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] protocol_version
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_protocol_version(CassCluster* cluster,
                                  int protocol_version);

/**
 * Sets the number of IO threads. This is the number of threads
 * that will handle query requests.
 *
 * Default: 1
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_threads
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_num_threads_io(CassCluster* cluster,
                                unsigned num_threads);

/**
 * Sets the size of the the fixed size queue that stores
 * pending requests.
 *
 * Default: 4096
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] queue_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_queue_size_io(CassCluster* cluster,
                               unsigned queue_size);

/**
 * Sets the size of the the fixed size queue that stores
 * events.
 *
 * Default: 4096
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] queue_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_queue_size_event(CassCluster* cluster,
                                  unsigned queue_size);

/**
 * Sets the size of the the fixed size queue that stores
 * log messages.
 *
 * Default: 4096
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] queue_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_queue_size_log(CassCluster* cluster,
                                unsigned queue_size);

/**
 * Sets the number of connections made to each server in each
 * IO thread.
 *
 * Default: 1
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_connections
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_core_connections_per_host(CassCluster* cluster,
                                           unsigned num_connections);

/**
 * Sets the maximum number of connections made to each server in each
 * IO thread.
 *
 * Default: 2
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_connections
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_max_connections_per_host(CassCluster* cluster,
                                          unsigned num_connections);

/**
 * Sets the amount of time to wait before attempting to reconnect.
 *
 * Default: 2000 milliseconds
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] wait_time
 */
CASS_EXPORT void
cass_cluster_set_reconnect_wait_time(CassCluster* cluster,
                                     unsigned wait_time);

/**
 * Sets the maximum number of connections that will be created concurrently.
 * Connections are created when the current connections are unable to keep up with
 * request throughput.
 *
 * Default: 1
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_connections
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_max_concurrent_creation(CassCluster* cluster,
                                         unsigned num_connections);

/**
 * Sets the threshold for the maximum number of concurrent requests in-flight
 * on a connection before creating a new connection. The number of new connections
 * created will not exceed max_connections_per_host.
 *
 * Default: 100
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_requests
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_max_concurrent_requests_threshold(CassCluster* cluster,
                                                   unsigned num_requests);

/**
 * Sets the maximum number of requests processed by an IO worker
 * per flush.
 *
 * Default: 128
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_requests
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_max_requests_per_flush(CassCluster* cluster,
                                        unsigned num_requests);

/**
 * Sets the high water mark for the number of bytes outstanding
 * on a connection. Disables writes to a connection if the number
 * of bytes queued exceed this value.
 *
 * Default: 64 KB
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_bytes
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_write_bytes_high_water_mark(CassCluster* cluster,
                                             unsigned num_bytes);

/**
 * Sets the low water mark for number of bytes outstanding on a
 * connection. After exceeding high water mark bytes, writes will
 * only resume once the number of bytes fall below this value.
 *
 * Default: 32 KB
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_bytes
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_write_bytes_low_water_mark(CassCluster* cluster,
                                            unsigned num_bytes);

/**
 * Sets the high water mark for the number of requests queued waiting
 * for a connection in a connection pool. Disables writes to a
 * host on an IO worker if the number of requests queued exceed this
 * value.
 *
 * Default: 128 * max_connections_per_host
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_requests
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_pending_requests_high_water_mark(CassCluster* cluster,
                                                  unsigned num_requests);

/**
 * Sets the low water mark for the number of requests queued waiting
 * for a connection in a connection pool. After exceeding high water mark
 * requests, writes to a host will only resume once the number of requests
 * fall below this value.
 *
 * Default: 64 * max_connections_per_host
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] num_requests
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_cluster_set_pending_requests_low_water_mark(CassCluster* cluster,
                                                 unsigned num_requests);

/**
 * Sets the timeout for connecting to a node.
 *
 * Default: 5000 milliseconds
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] timeout_ms Connect timeout in milliseconds
 */
CASS_EXPORT void
cass_cluster_set_connect_timeout(CassCluster* cluster,
                                 unsigned timeout_ms);

/**
 * Sets the timeout for waiting for a response from a node.
 *
 * Default: 12000 milliseconds
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] timeout_ms Request timeout in milliseconds
 */
CASS_EXPORT void
cass_cluster_set_request_timeout(CassCluster* cluster,
                                 unsigned timeout_ms);

/**
 * Sets credentials for plain text authentication.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] username
 * @param[in] password
 */
CASS_EXPORT void
cass_cluster_set_credentials(CassCluster* cluster,
                             const char* username,
                             const char* password);

/**
  * @see cass_cluster_set_credentials();
  */
CASS_EXPORT void
cass_cluster_set_credentials_n(CassCluster* cluster,
                               const char* username,
                               size_t username_length,
                               const char* password,
                               size_t password_length);

/**
 * Configures the cluster to use round-robin load balancing.
 *
 * The driver discovers all nodes in a cluster and cycles through
 * them per request. All are considered 'local'.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 */
CASS_EXPORT void
cass_cluster_set_load_balance_round_robin(CassCluster* cluster);

/**
 * Configures the cluster to use DC-aware load balancing.
 * For each query, all live nodes in a primary 'local' DC are tried first,
 * followed by any node from other DCs.
 *
 * Note: This is the default, and does not need to be called unless
 * switching an existing from another policy or changing settings.
 * Without further configuration, a default local_dc is chosen from the
 * first connected contact point, and no remote hosts are considered in
 * query plans. If relying on this mechanism, be sure to use only contact
 * points from the local DC.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] local_dc The primary data center to try first
 * @param[in] used_hosts_per_remote_dc The number of host used in each remote DC if no hosts
 * are available in the local dc
 * @param[in] allow_remote_dcs_for_local_cl Allows remote hosts to be used if no local dc hosts
 * are available and the consistency level is LOCAL_ONE or LOCAL_QUORUM
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT CassError
cass_cluster_set_load_balance_dc_aware(CassCluster* cluster,
                                       const char* local_dc,
                                       unsigned used_hosts_per_remote_dc,
                                       cass_bool_t allow_remote_dcs_for_local_cl);


/**
  * @see cass_cluster_set_load_balance_dc_aware()
  */
CASS_EXPORT CassError
cass_cluster_set_load_balance_dc_aware_n(CassCluster* cluster,
                                         const char* local_dc,
                                         size_t local_dc_length,
                                         unsigned used_hosts_per_remote_dc,
                                         cass_bool_t allow_remote_dcs_for_local_cl);

/**
 * Configures the cluster to use token-aware request routing, or not.
 *
 * Default is cass_true (enabled).
 *
 * This routing policy composes the base routing policy, routing
 * requests first to replicas on nodes considered 'local' by
 * the base load balancing policy.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] enabled
 */
CASS_EXPORT void
cass_cluster_set_token_aware_routing(CassCluster* cluster,
                                     cass_bool_t enabled);


/**
 * Configures the cluster to use latency-aware request routing, or not.
 *
 * Default is cass_true (enabled).
 *
 * This routing policy is a top-level routing policy. It uses the
 * base routing policy to determine locality (dc-aware) and/or
 * placement (token-aware) before considering the latency.
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] enabled
 */
CASS_EXPORT void
cass_cluster_set_latency_aware_routing(CassCluster* cluster,
                                       cass_bool_t enabled);

/**
 * Configures the settings for latency-aware request routing.
 *
 * Defaults:
 *
 * exclusion_threshold: 2.0
 * scale_ms: 100 milliseconds
 * retry_period_ms: 10,000 milliseconds (10 seconds)
 * update_rate_ms: 100 milliseconds
 * min_measured: 50
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] exclusion_threshold Controls how much worse the latency must be compared to the
 * average latency of the best performing node before it penalized.
 * @param[in] scale_ms Controls the weight given to older latencies when calculating the average
 * latency of a node. A bigger scale will give more weight to older latency measurements.
 * @param[in] retry_period_ms The amount of time a node is penalized by the policy before
 * being given a second chance when the current average latency exceeds the calculated
 * threshold (exclusion_threshold * best_average_latency).
 * @param[in] update_rate_ms The rate at  which the best average latency is recomputed.
 * @param[in] min_measured The minimum number of measurements per-host required to
 * be considered by the policy.
 */
CASS_EXPORT void
cass_cluster_set_latency_aware_routing_settings(CassCluster* cluster,
                                                cass_double_t exclusion_threshold,
                                                cass_uint64_t scale_ms,
                                                cass_uint64_t retry_period_ms,
                                                cass_uint64_t update_rate_ms,
                                                cass_uint64_t min_measured);

/**
 * Enable/Disable Nagel's algorithm on connections.
 *
 * Default: cass_false (disabled).
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] enabled
 */
CASS_EXPORT void
cass_cluster_set_tcp_nodelay(CassCluster* cluster,
                             cass_bool_t enabled);

/**
 * Enable/Disable TCP keep-alive
 *
 * Default: cass_false (disabled).
 *
 * @public @memberof CassCluster
 *
 * @param[in] cluster
 * @param[in] enabled
 * @param[in] delay_secs The initial delay in seconds, ignored when
 * `enabled` is false.
 */
CASS_EXPORT void
cass_cluster_set_tcp_keepalive(CassCluster* cluster,
                               cass_bool_t enabled,
                               unsigned delay_secs);

/***********************************************************************************
 *
 * Session
 *
 ***********************************************************************************/

/**
 * Creates a new session.
 *
 * @public @memberof CassSession
 *
 * @return Returns a session that must be freed.
 *
 * @see cass_session_free()
 */
CASS_EXPORT CassSession*
cass_session_new();

/**
 * Frees a session instance. If the session is still connected it will be synchronously
 * closed before being deallocated.
 *
 * Important: Do not free a session in a future callback. Freeing a session in a future
 * callback will cause a deadlock.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 */
CASS_EXPORT void
cass_session_free(CassSession* session);

/**
 * Connects a session.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[in] cluster
 * @return A future that must be freed.
 *
 * @see cass_session_close()
 */
CASS_EXPORT CassFuture*
cass_session_connect(CassSession* session,
                     const CassCluster* cluster);

/**
 * Connects a session and sets the keyspace.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[in] cluster
 * @param[in] keyspace
 * @return A future that must be freed.
 *
 * @see cass_session_close()
 */
CASS_EXPORT CassFuture*
cass_session_connect_keyspace(CassSession* session,
                              const CassCluster* cluster,
                              const char* keyspace);

/**
  * @see cass_session_connect_keyspace()
  */
CASS_EXPORT CassFuture*
cass_session_connect_keyspace_n(CassSession* session,
                                const CassCluster* cluster,
                                const char* keyspace,
                                size_t keyspace_length);

/**
 * Closes the session instance, outputs a close future which can
 * be used to determine when the session has been terminated. This allows
 * in-flight requests to finish.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @return A future that must be freed.
 */
CASS_EXPORT CassFuture*
cass_session_close(CassSession* session);

/**
 * Create a prepared statement.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[in] query The query is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @return A future that must be freed.
 *
 * @see cass_future_get_prepared()
 */
CASS_EXPORT CassFuture*
cass_session_prepare(CassSession* session,
                     const char* query);

/**
  * @see cass_session_prepare()
  */
CASS_EXPORT CassFuture*
cass_session_prepare_n(CassSession* session,
                       const char* query,
                       size_t query_length);

/**
 * Execute a query or bound statement.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[in] statement
 * @return A future that must be freed.
 *
 * @see cass_future_get_result()
 */
CASS_EXPORT CassFuture*
cass_session_execute(CassSession* session,
                     const CassStatement* statement);

/**
 * Execute a batch statement.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[in] batch
 * @return A future that must be freed.
 *
 * @see cass_future_get_result()
 */
CASS_EXPORT CassFuture*
cass_session_execute_batch(CassSession* session,
                           const CassBatch* batch);

/**
 * Gets a copy of this session's schema metadata. The returned
 * copy of the schema metadata is not updated. This function
 * must be called again to retrieve any schema changes since the
 * previous call.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @return A schema instance that must be freed.
 *
 * @see cass_schema_free()
 */
CASS_EXPORT const CassSchema*
cass_session_get_schema(CassSession* session);

/**
 * Gets a copy of this session's performance/diagnostic metrics.
 *
 * @public @memberof CassSession
 *
 * @param[in] session
 * @param[out] output
 *
 * @see cass_schema_free()
 */
CASS_EXPORT void
cass_session_get_metrics(CassSession* session,
                         CassMetrics* output);

/***********************************************************************************
 *
 * Schema metadata
 *
 ***********************************************************************************/

/**
 * Frees a schema instance.
 *
 * @public @memberof CassSchema
 *
 * @param[in] schema
 */
CASS_EXPORT void
cass_schema_free(const CassSchema* schema);

/**
 * Gets a the metadata for the provided keyspace name.
 *
 * @public @memberof CassSchema
 *
 * @param[in] schema
 * @param[in] keyspace_name
 * @return The schema metadata for a keyspace. NULL if keyspace does not exist.
 *
 * @see cass_schema_meta_get_entry()
 * @see cass_schema_meta_get_field()
 * @see cass_schema_meta_type()
 * @see cass_iterator_from_schema_meta()
 */
CASS_EXPORT const CassSchemaMeta*
cass_schema_get_keyspace(const CassSchema* schema,
                         const char* keyspace);

/**
  * @see cass_schema_get_keyspace()
  */
CASS_EXPORT const CassSchemaMeta*
cass_schema_get_keyspace_n(const CassSchema* schema,
                           const char* keyspace,
                           size_t keyspace_length);

/**
 * Gets the type of the specified schema metadata.
 *
 * @public @memberof CassSchema
 *
 * @param[in] meta
 * @return The type of the schema metadata
 */
CASS_EXPORT CassSchemaMetaType
cass_schema_meta_type(const CassSchemaMeta* meta);

/**
 * Gets a metadata entry for the provided table/column name.
 *
 * @public @memberof CassSchemaMeta
 *
 * @param[in] meta
 * @param[in] name The name of a table or column
 * @return The schema metadata for a table/column. NULL if table/column does not exist.
 *
 * @see cass_schema_meta_get_entry()
 * @see cass_schema_meta_get_field()
 * @see cass_schema_meta_type()
 * @see cass_iterator_from_schema_meta()
 * @see cass_iterator_fields_from_schema_meta()
 */
CASS_EXPORT const CassSchemaMeta*
cass_schema_meta_get_entry(const CassSchemaMeta* meta,
                           const char* name);

/**
  * @see cass_schema_meta_get_entry()
  */
CASS_EXPORT const CassSchemaMeta*
cass_schema_meta_get_entry_n(const CassSchemaMeta* meta,
                             const char* name,
                             size_t name_length);

/**
 * Gets a metadata field for the provided name.
 *
 * @public @memberof CassSchemaMeta
 *
 * @param[in] meta
 * @param[in] name The name of a field
 * @return A schema metadata field. NULL if the field does not exist.
 *
 * @see cass_schema_meta_field_value()
 */
CASS_EXPORT const CassSchemaMetaField*
cass_schema_meta_get_field(const CassSchemaMeta* meta,
                           const char* name);

/**
  * @see cass_schema_meta_get_field()
  */
CASS_EXPORT const CassSchemaMetaField*
cass_schema_meta_get_field_n(const CassSchemaMeta* meta,
                             const char* name,
                             size_t name_length);

/**
 * Gets the name for a schema metadata field
 *
 * @public @memberof CassSchemaMetaField
 *
 * @param[in] field
 * @param[out] name The name of the metadata data field
 * @param[out] name_length
 */
CASS_EXPORT void
cass_schema_meta_field_name(const CassSchemaMetaField* field,
                            const char** name,
                            size_t* name_length);

/**
 * Gets the value for a schema metadata field
 *
 * @public @memberof CassSchemaMetaField
 *
 * @param[in] field
 * @return The value of the metadata data field
 */
CASS_EXPORT const CassValue*
cass_schema_meta_field_value(const CassSchemaMetaField* field);

/***********************************************************************************
 *
 * SSL
 *
 ************************************************************************************/

/**
 * Creates a new SSL context.
 *
 * @public @memberof CassSsl
 *
 * @return Returns a SSL context that must be freed.
 *
 * @see cass_ssl_free()
 */
CASS_EXPORT CassSsl*
cass_ssl_new();

/**
 * Frees a SSL context instance.
 *
 * @public @memberof CassSsl
 *
 * @param[in] ssl
 */
CASS_EXPORT void
cass_ssl_free(CassSsl* ssl);

/**
 * Adds a trusted certificate. This is used to verify
 * the peer's certificate.
 *
 * @public @memberof CassSsl
 *
 * @param[in] ssl
 * @param[in] cert PEM formatted certificate string
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT CassError
cass_ssl_add_trusted_cert(CassSsl* ssl,
                          const char* cert);

/**
  * @see cass_ssl_add_trusted_cert()
  */
CASS_EXPORT CassError
cass_ssl_add_trusted_cert_n(CassSsl* ssl,
                            const char* cert,
                            size_t);

/**
 * Sets verification performed on the peer's certificate.
 *
 * CASS_SSL_VERIFY_NONE - No verification is performed
 * CASS_SSL_VERIFY_PEER_CERT - Certificate is present and valid
 * CASS_SSL_VERIFY_PEER_IDENTITY - IP address matches the certificate's
 * common name or one of its subject alternative names. This implies the
 * certificate is also present.
 *
 * Default: CASS_SSL_VERIFY_PEER_CERT
 *
 * @public @memberof CassSsl
 *
 * @param[in] ssl
 * @param[in] flags
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT void
cass_ssl_set_verify_flags(CassSsl* ssl,
                          int flags);

/**
 * Set client-side certificate chain. This is used to authenticate
 * the client on the server-side. This should contain the entire
 * Certificate chain starting with the certificate itself.
 *
 * @public @memberof CassSsl
 *
 * @param[in] ssl
 * @param[in] cert PEM formatted certificate string
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT CassError
cass_ssl_set_cert(CassSsl* ssl,
                  const char* cert);

/**
  * @see cass_ssl_set_cert()
  */
CASS_EXPORT CassError
cass_ssl_set_cert_n(CassSsl* ssl,
                    const char* cert,
                    size_t cert_length);

/**
 * Set client-side private key. This is used to authenticate
 * the client on the server-side.
 *
 * @public @memberof CassSsl
 *
 * @param[in] ssl
 * @param[in] key PEM formatted key string
 * @param[in] password used to decrypt key
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT CassError
cass_ssl_set_private_key(CassSsl* ssl,
                         const char* key,
                         const char* password);

/**
  * @see cass_ssl_set_private_key()
  */
CASS_EXPORT CassError
cass_ssl_set_private_key_n(CassSsl* ssl,
                           const char* key,
                           size_t key_length,
                           const char* password,
                           size_t password_length);

/***********************************************************************************
 *
 * Future
 *
 ***********************************************************************************/

/**
 * Frees a future instance. A future can be freed anytime.
 *
 * @public @memberof CassFuture
 */
CASS_EXPORT void
cass_future_free(CassFuture* future);

/**
 * Sets a callback that is called when a future is set
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @param[in] callback
 * @param[in] data
 * @return CASS_OK if successful, otherwise an error occurred
 */
CASS_EXPORT CassError
cass_future_set_callback(CassFuture* future,
                         CassFutureCallback callback,
                         void* data);

/**
 * Gets the set status of the future.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @return true if set
 */
CASS_EXPORT cass_bool_t
cass_future_ready(CassFuture* future);

/**
 * Wait for the future to be set with either a result or error.
 *
 * Important: Do not wait in a future callback. Waiting in a future
 * callback will cause a deadlock.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 */
CASS_EXPORT void
cass_future_wait(CassFuture* future);

/**
 * Wait for the future to be set or timeout.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @param[in] timeout_us wait time in microseconds
 * @return false if returned due to timeout
 */
CASS_EXPORT cass_bool_t
cass_future_wait_timed(CassFuture* future,
                       cass_duration_t timeout_us);

/**
 * Gets the result of a successful future. If the future is not ready this method will
 * wait for the future to be set. The first successful call consumes the future, all
 * subsequent calls will return NULL.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @return CassResult instance if successful, otherwise NULL for error. The return instance
 * must be freed using cass_result_free().
 *
 * @see cass_session_execute() and cass_session_execute_batch()
 */
CASS_EXPORT const CassResult*
cass_future_get_result(CassFuture* future);

/**
 * Gets the result of a successful future. If the future is not ready this method will
 * wait for the future to be set. The first successful call consumes the future, all
 * subsequent calls will return NULL.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @return CassPrepared instance if successful, otherwise NULL for error. The return instance
 * must be freed using cass_prepared_free().
 *
 * @see cass_session_prepare()
 */
CASS_EXPORT const CassPrepared*
cass_future_get_prepared(CassFuture* future);

/**
 * Gets the error code from future. If the future is not ready this method will
 * wait for the future to be set.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @return CASS_OK if successful, otherwise an error occurred.
 *
 * @see cass_error_desc()
 */
CASS_EXPORT CassError
cass_future_error_code(CassFuture* future);

/**
 * Gets the error message from future. If the future is not ready this method will
 * wait for the future to be set.
 *
 * @public @memberof CassFuture
 *
 * @param[in] future
 * @param[out] message Empty string returned if successful, otherwise
 * a message describing the error is returned.
 * @param[out] message_length
 */
CASS_EXPORT void
cass_future_error_message(CassFuture* future,
                          const char** message,
                          size_t* message_length);

/***********************************************************************************
 *
 * Statement
 *
 ***********************************************************************************/

/**
 * Creates a new query statement.
 *
 * @public @memberof CassStatement
 *
 * @param[in] query The query is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] parameter_count The number of bound parameters.
 * @return Returns a statement that must be freed.
 *
 * @see cass_statement_free()
 */
CASS_EXPORT CassStatement*
cass_statement_new(const char* query,
                   size_t parameter_count);

/**
  * @see cass_statement_new()
  */
CASS_EXPORT CassStatement*
cass_statement_new_n(const char* query,
                     size_t query_length,
                     size_t parameter_count);

/**
 * Frees a statement instance. Statements can be immediately freed after
 * being prepared, executed or added to a batch.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 */
CASS_EXPORT void
cass_statement_free(CassStatement* statement);

/**
 * Adds a key index specifier to this a statement.
 * When using token-aware routing, this can be used to tell the driver which
 * parameters within a non-prepared, parameterized statement are part of
 * the partition key.
 *
 * Use consecutive calls for composite partition keys.
 *
 * This is not necessary for prepared statements, as the key
 * parameters are determined in the metadata processed in the prepare phase.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_add_key_index(CassStatement* statement,
                             size_t index);


/**
 * Sets the statement's keyspace for use with token-aware routing.
 *
 * This is not necessary for prepared statements, as the keyspace
 * is determined in the metadata processed in the prepare phase.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] keyspace
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_set_keyspace(CassStatement* statement,
                            const char* keyspace);

/**
  * @see cass_statement_set_keyspace()
  */
CASS_EXPORT CassError
cass_statement_set_keyspace_n(CassStatement* statement,
                              const char* keyspace,
                              size_t keyspace_length);

/**
 * Sets the statement's consistency level.
 *
 * Default: CASS_CONSISTENCY_ONE
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] consistency
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_set_consistency(CassStatement* statement,
                               CassConsistency consistency);

/**
 * Sets the statement's serial consistency level.
 *
 * Default: Not set
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] serial_consistency
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_set_serial_consistency(CassStatement* statement,
                                      CassConsistency serial_consistency);

/**
 * Sets the statement's page size.
 *
 * Default: -1 (Disabled)
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] page_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_set_paging_size(CassStatement* statement,
                               int page_size);

/**
 * Sets the statement's paging state.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] result
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_set_paging_state(CassStatement* statement,
                                const CassResult* result);

/**
 * Binds null to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_null(CassStatement* statement,
                         size_t index);

/**
 * Binds an "int" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_int32(CassStatement* statement,
                          size_t index,
                          cass_int32_t value);

/**
 * Binds a "bigint", "counter" or "timestamp" to a query or bound statement
 * at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_int64(CassStatement* statement,
                          size_t index,
                          cass_int64_t value);

/**
 * Binds a "float" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_float(CassStatement* statement,
                          size_t index,
                          cass_float_t value);

/**
 * Binds a "double" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_double(CassStatement* statement,
                           size_t index,
                           cass_double_t value);

/**
 * Binds a "boolean" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_bool(CassStatement* statement,
                         size_t index,
                         cass_bool_t value);

/**
 * Binds a "ascii", "text" or "varchar" to a query or bound statement
 * at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_string(CassStatement* statement,
                           size_t index,
                           const char* value);

/**
  * @see cass_statement_bind_string()
  */
CASS_EXPORT CassError
cass_statement_bind_string_n(CassStatement* statement,
                             size_t index,
                             const char* value,
                             size_t value_length);

/**
 * Binds a "blob" or "varint" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] value_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_bytes(CassStatement* statement,
                          size_t index,
                          const cass_uint8_t* value,
                          size_t value_size);

/**
 * Binds a "uuid" or "timeuuid" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_uuid(CassStatement* statement,
                         size_t index,
                         CassUuid value);

/**
 * Binds an "inet" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_inet(CassStatement* statement,
                         size_t index,
                         CassInet value);

/**
 * Bind a "decimal" to a query or bound statement at the specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] varint The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] varint_size
 * @param[in] scale
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_decimal(CassStatement* statement,
                            size_t index,
                            const cass_byte_t* varint,
                            size_t varint_size,
                            cass_int32_t scale);

/**
 * Binds any type to a query or bound statement at the specified index. A value
 * can be copied into the resulting output buffer. This is normally reserved for
 * large values to avoid extra memory copies.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] size
 * @param[out] output
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_custom(CassStatement* statement,
                           size_t index,
                           size_t size,
                           cass_byte_t** output);

/**
 * Bind a "list", "map", or "set" to a query or bound statement at the
 * specified index.
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] index
 * @param[in] collection The collection can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_collection(CassStatement* statement,
                               size_t index,
                               const CassCollection* collection);


CASS_EXPORT CassError
cass_statement_bind_null_by_name(CassStatement* statement,
                                 const char* name);
/**
  * @see cass_statement_bind_null_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_null_by_name_n(CassStatement* statement,
                                   const char* name,
                                   size_t name_length);

/**
 * Binds a null to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_null_by_name(CassStatement* statement,
                                 const char* name);

/**
 * Binds an "int" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_int32_by_name(CassStatement* statement,
                                  const char* name,
                                  cass_int32_t value);

/**
  * @see cass_statement_bind_int32_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_int32_by_name_n(CassStatement* statement,
                                    const char* name,
                                    size_t name_length,
                                    cass_int32_t value);

/**
 * Binds a "bigint", "counter" or "timestamp" to all values
 * with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_int64_by_name(CassStatement* statement,
                                  const char* name,
                                  cass_int64_t value);

/**
  * @see cass_statement_bind_int64_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_int64_by_name_n(CassStatement* statement,
                                    const char* name,
                                    size_t name_length,
                                    cass_int64_t value);

/**
 * Binds a "float" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_float_by_name(CassStatement* statement,
                                  const char* name,
                                  cass_float_t value);

/**
  * @see cass_statement_bind_float_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_float_by_name_n(CassStatement* statement,
                                    const char* name,
                                    size_t name_length,
                                    cass_float_t value);

/**
 * Binds a "double" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_double_by_name(CassStatement* statement,
                                   const char* name,
                                   cass_double_t value);

/**
  * @see cass_statement_bind_double_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_double_by_name_n(CassStatement* statement,
                                     const char* name,
                                     size_t name_length,
                                     cass_double_t value);
/**
 * Binds a "boolean" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_bool_by_name(CassStatement* statement,
                                 const char* name,
                                 cass_bool_t value);

/**
  * @see cass_statement_bind_bool_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_bool_by_name_n(CassStatement* statement,
                                   const char* name,
                                   size_t name_length,
                                   cass_bool_t value);

/**
 * Binds a "ascii", "text" or "varchar" to all the values
 * with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_string_by_name(CassStatement* statement,
                                   const char* name,
                                   const char* value);

/**
  * @see cass_statement_bind_string_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_string_by_name_n(CassStatement* statement,
                                     const char* name,
                                     size_t name_length,
                                     const char* value,
                                     size_t value_length);

/**
 * Binds a "blob" or "varint" to all the values with the
 * specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] value_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_bytes_by_name(CassStatement* statement,
                                  const char* name,
                                  cass_uint8_t* value,
                                  size_t value_size);

/**
  * @see cass_statement_bind_bytes_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_bytes_by_name_n(CassStatement* statement,
                                    const char* name,
                                    size_t name_length,
                                    cass_uint8_t* value,
                                    size_t value_size);

/**
 * Binds a "uuid" or "timeuuid" to all the values
 * with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_uuid_by_name(CassStatement* statement,
                                 const char* name,
                                 CassUuid value);

/**
  * @see cass_statement_bind_uuid_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_uuid_by_name_n(CassStatement* statement,
                                   const char* name,
                                   size_t name_length,
                                   CassUuid value);

/**
 * Binds an "inet" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_inet_by_name(CassStatement* statement,
                                 const char* name,
                                 CassInet value);

/**
  * @see cass_statement_bind_inet_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_inet_by_name_n(CassStatement* statement,
                                   const char* name,
                                   size_t name_length,
                                   CassInet value);

/**
 * Binds a "decimal" to all the values with the specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] varint The value is copied into the statement object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] varint_size
 * @param[in] scale
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_decimal_by_name(CassStatement* statement,
                                    const char* name,
                                    const cass_byte_t* varint,
                                    size_t varint_size,
                                    cass_int32_t scale);

/**
  * @see cass_statement_bind_decimal_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_decimal_by_name_n(CassStatement* statement,
                                      const char* name,
                                      size_t name_length,
                                      const cass_byte_t* varint,
                                      size_t varint_size,
                                      cass_int32_t scale);

/**
 * Binds any type to all the values with the specified name. A value
 * can be copied into the resulting output buffer. This is normally reserved for
 * large values to avoid extra memory copies.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] size
 * @param[out] output
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_custom_by_name(CassStatement* statement,
                                   const char* name,
                                   size_t size,
                                   cass_byte_t** output);

/**
  * @see cass_statement_bind_custom_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_custom_by_name_n(CassStatement* statement,
                                     const char* name,
                                     size_t name_length,
                                     size_t size,
                                     cass_byte_t** output);

/**
 * Bind a "list", "map", or "set" to all the values with the
 * specified name.
 *
 * This can only be used with statements created by
 * cass_prepared_bind().
 *
 * @public @memberof CassStatement
 *
 * @param[in] statement
 * @param[in] name
 * @param[in] collection The collection can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_statement_bind_collection_by_name(CassStatement* statement,
                                       const char* name,
                                       const CassCollection* collection);

/**
  * @see cass_statement_bind_collection_by_name()
  */
CASS_EXPORT CassError
cass_statement_bind_collection_by_name_n(CassStatement* statement,
                                         const char* name,
                                         size_t name_length,
                                         const CassCollection* collection);


/***********************************************************************************
 *
 * Prepared
 *
 ***********************************************************************************/

/**
 * Frees a prepared instance.
 *
 * @public @memberof CassPrepared
 *
 * @param[in] prepared
 */
CASS_EXPORT void
cass_prepared_free(const CassPrepared* prepared);

/**
 * Creates a bound statement from a pre-prepared statement.
 *
 * @public @memberof CassPrepared
 *
 * @param[in] prepared A previously prepared statement.
 * @return Returns a bound statement that must be freed.
 *
 * @see cass_statement_free()
 */
CASS_EXPORT CassStatement*
cass_prepared_bind(const CassPrepared* prepared);

/***********************************************************************************
 *
 * Batch
 *
 ***********************************************************************************/

/**
 * Creates a new batch statement with batch type.
 *
 * @public @memberof CassBatch
 *
 * @param[in] type
 * @return Returns a batch statement that must be freed.
 *
 * @see cass_batch_free()
 */
CASS_EXPORT CassBatch*
cass_batch_new(CassBatchType type);

/**
 * Frees a batch instance. Batches can be immediately freed after being
 * executed.
 *
 * @public @memberof CassBatch
 *
 * @param[in] batch
 */
CASS_EXPORT void
cass_batch_free(CassBatch* batch);

/**
 * Sets the batch's consistency level
 *
 * @public @memberof CassBatch
 *
 * @param[in] batch
 * @param[in] consistency The batch's write consistency.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_batch_set_consistency(CassBatch* batch,
                           CassConsistency consistency);

/**
 * Adds a statement to a batch.
 *
 * @public @memberof CassBatch
 *
 * @param[in] batch
 * @param[in] statement
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_batch_add_statement(CassBatch* batch,
                         CassStatement* statement);


/***********************************************************************************
 *
 * Collection
 *
 ***********************************************************************************/

/**
 * Creates a new collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] type
 * @param[in] item_count The approximate number of items in the collection.
 * @return Returns a collection that must be freed.
 *
 * @see cass_collection_free()
 */
CASS_EXPORT CassCollection*
cass_collection_new(CassCollectionType type, size_t item_count);

/**
 * Frees a collection instance.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 */
CASS_EXPORT void
cass_collection_free(CassCollection* collection);

/**
 * Appends an "int" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_int32(CassCollection* collection,
                             cass_int32_t value);

/**
 * Appends a "bigint", "counter" or "timestamp" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_int64(CassCollection* collection,
                             cass_int64_t value);

/**
 * Appends a "float" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_float(CassCollection* collection,
                             cass_float_t value);

/**
 * Appends a "double" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_double(CassCollection* collection,
                              cass_double_t value);

/**
 * Appends a "boolean" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_bool(CassCollection* collection,
                            cass_bool_t value);

/**
 * Appends a "ascii", "text" or "varchar" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value The value is copied into the collection object; the
 * memory pointed to by this parameter can be freed after this call.
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_string(CassCollection* collection,
                              const char* value);


/**
  * @see cass_collection_append_string_n();
  */
CASS_EXPORT CassError
cass_collection_append_string_n(CassCollection* collection,
                                const char* value,
                                size_t value_length);

/**
 * Appends a "blob" or "varint" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value The value is copied into the collection object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] value_size
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_bytes(CassCollection* collection,
                             const cass_byte_t* value,
                             size_t value_size);

/**
 * Appends a "uuid" or "timeuuid"  to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_uuid(CassCollection* collection,
                            CassUuid value);

/**
 * Appends an "inet" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] value
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_inet(CassCollection* collection,
                            CassInet value);

/**
 * Appends a "decimal" to the collection.
 *
 * @public @memberof CassCollection
 *
 * @param[in] collection
 * @param[in] varint The value is copied into the collection object; the
 * memory pointed to by this parameter can be freed after this call.
 * @param[in] varint_size
 * @param[in] scale
 * @return CASS_OK if successful, otherwise an error occurred.
 */
CASS_EXPORT CassError
cass_collection_append_decimal(CassCollection* collection,
                               const cass_byte_t* varint,
                               size_t varint_size,
                               cass_int32_t scale);

/***********************************************************************************
 *
 * Result
 *
 ***********************************************************************************/

/**
 * Frees a result instance.
 *
 * This method invalidates all values, rows, and
 * iterators that were derived from this result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 */
CASS_EXPORT void
cass_result_free(const CassResult* result);

/**
 * Gets the number of rows for the specified result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @return The number of rows in the result.
 */
CASS_EXPORT size_t
cass_result_row_count(const CassResult* result);

/**
 * Gets the number of columns per row for the specified result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @return The number of columns per row in the result.
 */
CASS_EXPORT size_t
cass_result_column_count(const CassResult* result);

/**
 * Gets the column name at index for the specified result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @param[in] index
 * @param[out] name The column name at the specified index.
 * @param[out] name_length
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_result_column_name(const CassResult *result,
                        size_t index,
                        const char** name,
                        size_t* name_length);

/**
 * Gets the column type at index for the specified result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @param[in] index
 * @return The column type at the specified index. CASS_VALUE_TYPE_UNKNOWN
 * is returned if the index is out of bounds.
 */
CASS_EXPORT CassValueType
cass_result_column_type(const CassResult* result,
                        size_t index);

/**
 * Gets the first row of the result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @return The first row of the result. NULL if there are no rows.
 */
CASS_EXPORT const CassRow*
cass_result_first_row(const CassResult* result);

/**
 * Returns true if there are more pages.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @return cass_true if there are more pages
 */
CASS_EXPORT cass_bool_t
cass_result_has_more_pages(const CassResult* result);

/***********************************************************************************
 *
 * Iterator
 *
 ***********************************************************************************/

/**
 * Frees an iterator instance.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 */
CASS_EXPORT void
cass_iterator_free(CassIterator* iterator);

/**
 * Gets the type of the specified iterator.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return The type of the iterator.
 */
CASS_EXPORT CassIteratorType
cass_iterator_type(CassIterator* iterator);

/**
 * Creates a new iterator for the specified result. This can be
 * used to iterate over rows in the result.
 *
 * @public @memberof CassResult
 *
 * @param[in] result
 * @return A new iterator that must be freed.
 *
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_result(const CassResult* result);

/**
 * Creates a new iterator for the specified row. This can be
 * used to iterate over columns in a row.
 *
 * @public @memberof CassRow
 *
 * @param[in] row
 * @return A new iterator that must be freed.
 *
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_row(const CassRow* row);

/**
 * Creates a new iterator for the specified collection. This can be
 * used to iterate over values in a collection.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @return A new iterator that must be freed. NULL returned if the
 * value is not a collection.
 *
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_collection(const CassValue* value);

/**
 * Creates a new iterator for the specified map. This can be
 * used to iterate over key/value pairs in a map.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @return A new iterator that must be freed. NULL returned if the
 * value is not a map.
 *
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_map(const CassValue* value);

/**
 * Creates a new iterator for the specified schema.
 * This can be used to iterate over keyspace entries.
 *
 * @public @memberof CassSchema
 *
 * @param[in] schema
 * @return A new iterator that must be freed.
 *
 * @see cass_iterator_get_schema_meta()
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_schema(const CassSchema* schema);

/**
 * Creates a new iterator for the specified schema metadata.
 * This can be used to iterate over table/column entries.
 *
 * @public @memberof CassSchemaMeta
 *
 * @param[in] meta
 * @return A new iterator that must be freed.
 *
 * @see cass_iterator_get_schema_meta()
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_from_schema_meta(const CassSchemaMeta* meta);

/**
 * Creates a new iterator for the specified schema metadata.
 * This can be used to iterate over schema metadata fields.
 *
 * @public @memberof CassSchemaMeta
 *
 * @param[in] meta
 * @return A new iterator that must be freed.
 *
 * @see cass_iterator_get_schema_meta_field()
 * @see cass_iterator_free()
 */
CASS_EXPORT CassIterator*
cass_iterator_fields_from_schema_meta(const CassSchemaMeta* meta);

/**
 * Advance the iterator to the next row, column, or collection item.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return false if no more rows, columns, or items, otherwise true
 */
CASS_EXPORT cass_bool_t
cass_iterator_next(CassIterator* iterator);

/**
 * Gets the row at the result iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * row returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A row
 */
CASS_EXPORT const CassRow*
cass_iterator_get_row(CassIterator* iterator);

/**
 * Gets the column value at the row iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * column returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A value
 */
CASS_EXPORT const CassValue*
cass_iterator_get_column(CassIterator* iterator);

/**
 * Gets the value at the collection iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * key returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A value
 */
CASS_EXPORT const CassValue*
cass_iterator_get_value(CassIterator* iterator);

/**
 * Gets the value at the collection iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * value returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A value
 */
CASS_EXPORT const CassValue*
cass_iterator_get_value(CassIterator* iterator);

/**
 * Gets the key at the map iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * value returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A value
 */
CASS_EXPORT const CassValue*
cass_iterator_get_map_key(CassIterator* iterator);


/**
 * Gets the value at the map iterator's current position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * value returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A value
 */
CASS_EXPORT const CassValue*
cass_iterator_get_map_value(CassIterator* iterator);

/**
 * Gets the schema metadata entry at the iterator's current
 * position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * value returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A keyspace/table/column schema metadata entry
 */
CASS_EXPORT const CassSchemaMeta*
cass_iterator_get_schema_meta(CassIterator* iterator);

/**
 * Gets the schema metadata field at the iterator's current
 * position.
 *
 * Calling cass_iterator_next() will invalidate the previous
 * value returned by this method.
 *
 * @public @memberof CassIterator
 *
 * @param[in] iterator
 * @return A schema metadata field
 */
CASS_EXPORT const CassSchemaMetaField*
cass_iterator_get_schema_meta_field(CassIterator* iterator);




/***********************************************************************************
 *
 * Row
 *
 ***********************************************************************************/

/**
 * Get the column value at index for the specified row.
 *
 * @public @memberof CassRow
 *
 * @param[in] row
 * @param[in] index
 * @return The column value at the specified index. NULL is
 * returned if the index is out of bounds.
 */
CASS_EXPORT const CassValue*
cass_row_get_column(const CassRow* row,
                    size_t index);


/**
 * Get the column value by name for the specified row.
 *
 * @public @memberof CassRow
 *
 * @param[in] row
 * @param[in] name
 * @return The column value for the specified name. NULL is
 * returned if the column does not exist.
 */
CASS_EXPORT const CassValue*
cass_row_get_column_by_name(const CassRow* row,
                            const char* name);

/**
  * @see cass_row_get_column_by_name()
  */
CASS_EXPORT const CassValue*
cass_row_get_column_by_name_n(const CassRow* row,
                              const char* name,
                              size_t name_length);

/***********************************************************************************
 *
 * Value
 *
 ***********************************************************************************/

/**
 * Gets an int32 for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_int32(const CassValue* value,
                     cass_int32_t* output);

/**
 * Gets an int64 for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_int64(const CassValue* value,
                     cass_int64_t* output);

/**
 * Gets a float for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_float(const CassValue* value,
                     cass_float_t* output);

/**
 * Gets a double for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_double(const CassValue* value,
                      cass_double_t* output);

/**
 * Gets a bool for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_bool(const CassValue* value,
                    cass_bool_t* output);

/**
 * Gets a UUID for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_uuid(const CassValue* value,
                    CassUuid* output);

/**
 * Gets an INET for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_inet(const CassValue* value,
                    CassInet* output);

/**
 * Gets a string for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @param[out] output_size
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_string(const CassValue* value,
                      const char** output,
                      size_t* output_size);

/**
 * Gets the bytes of the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] output
 * @param[out] output_size
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_bytes(const CassValue* value,
                     const cass_byte_t** output,
                     size_t* output_size);



/**
 * Gets a decimal for the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @param[out] varint
 * @param[out] varint_size
 * @param[out] scale
 * @return CASS_OK if successful, otherwise error occurred
 */
CASS_EXPORT CassError
cass_value_get_decimal(const CassValue* value,
                       const cass_byte_t** varint,
                       size_t* varint_size,
                       cass_int32_t* scale);

/**
 * Gets the type of the specified value.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @return The type of the specified value.
 */
CASS_EXPORT CassValueType
cass_value_type(const CassValue* value);

/**
 * Returns true if a specified value is null.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @return true if the value is null, otherwise false.
 */
CASS_EXPORT cass_bool_t
cass_value_is_null(const CassValue* value);

/**
 * Returns true if a specified value is a collection.
 *
 * @public @memberof CassValue
 *
 * @param[in] value
 * @return true if the value is a collection, otherwise false.
 */
CASS_EXPORT cass_bool_t
cass_value_is_collection(const CassValue* value);

/**
 * Get the number of items in a collection. Works for all collection types.
 *
 * @public @memberof CassValue
 *
 * @param[in] collection
 * @return Count of items in a collection. 0 if not a collection.
 */
CASS_EXPORT size_t
cass_value_item_count(const CassValue* collection);

/**
 * Get the primary sub-type for a collection. This returns the sub-type for a
 * list or set and the key type for a map.
 *
 * @public @memberof CassValue
 *
 * @param[in] collection
 * @return The type of the primary sub-type. CASS_VALUE_TYPE_UNKNOWN
 * returned if not a collection.
 */
CASS_EXPORT CassValueType
cass_value_primary_sub_type(const CassValue* collection);

/**
 * Get the secondary sub-type for a collection. This returns the value type for a
 * map.
 *
 * @public @memberof CassValue
 *
 * @param[in] collection
 * @return The type of the primary sub-type. CASS_VALUE_TYPE_UNKNOWN
 * returned if not a collection or not a map.
 */
CASS_EXPORT CassValueType
cass_value_secondary_sub_type(const CassValue* collection);


/***********************************************************************************
 *
 * UUID
 *
 ************************************************************************************/

/**
 * Creates a new UUID generator.
 *
 * Note: This object is thread-safe. It is best practice to create and reuse
 * a single object per application.
 *
 * Note: If unique node information (IP address) is unable to be determined
 * then random node information will be generated.
 *
 * @public @memberof CassUuidGen
 *
 * @return Returns a UUID generator that must be freed.
 *
 * @see cass_uuid_gen_free()
 * @see cass_uuid_gen_new_with_node()
 */
CASS_EXPORT CassUuidGen*
cass_uuid_gen_new();

/**
 * Creates a new UUID generator with custom node information.
 *
 * Note: This object is thread-safe. It is best practice to create and reuse
 * a single object per application.
 *
 * @public @memberof CassUuidGen
 *
 * @return Returns a UUID generator that must be freed.
 *
 * @see cass_uuid_gen_free()
 */
CASS_EXPORT CassUuidGen*
cass_uuid_gen_new_with_node(cass_uint64_t node);

/**
 * Frees a UUID generator instance.
 *
 * @public @memberof CassUuidGen
 *
 * @param[in] uuid_gen
 */
CASS_EXPORT void
cass_uuid_gen_free(CassUuidGen* uuid_gen);

/**
 * Generates a V1 (time) UUID.
 *
 * Note: This method is thread-safe
 *
 * @public @memberof CassUuidGen
 *
 * @param[in] uuid_gen
 * @param[out] output A V1 UUID for the current time.
 */
CASS_EXPORT void
cass_uuid_gen_time(CassUuidGen* uuid_gen,
                   CassUuid* output);

/**
 * Generates a new V4 (random) UUID
 *
 * Note: This method is thread-safe
 *
 * @public @memberof CassUuidGen
 *
 * @param[in] uuid_gen
 * @param output A randomly generated V4 UUID.
 */
CASS_EXPORT void
cass_uuid_gen_random(CassUuidGen* uuid_gen,
                     CassUuid* output);

/**
 * Generates a V1 (time) UUID for the specified time.
 *
 * Note: This method is thread-safe
 *
 * @public @memberof CassUuidGen
 *
 * @param[in] uuid_gen
 * @param[in] timestamp
 * @param[out] output A V1 UUID for the specified time.
 */
CASS_EXPORT void
cass_uuid_gen_from_time(CassUuidGen* uuid_gen,
                        cass_uint64_t timestamp,
                        CassUuid* output);

/**
 * Sets the UUID to the minimum V1 (time) value for the specified time.
 *
 * @public @memberof CassUuid
 *
 * @param[in] time
 * @param[out] output A minimum V1 UUID for the specified time.
 */
CASS_EXPORT void
cass_uuid_min_from_time(cass_uint64_t time,
                        CassUuid* output);

/**
 * Sets the UUID to the maximum V1 (time) value for the specified time.
 *
 * @public @memberof CassUuid
 *
 * @param[in] time
 * @param[out] output A maximum V1 UUID for the specified time.
 */
CASS_EXPORT void
cass_uuid_max_from_time(cass_uint64_t time,
                        CassUuid* output);

/**
 * Gets the timestamp for a V1 UUID
 *
 * @public @memberof CassUuid
 *
 * @param[in] uuid
 * @return The timestamp in milliseconds since the Epoch
 * (00:00:00 UTC on 1 January 1970). 0 returned if the UUID
 * is not V1.
 */
CASS_EXPORT cass_uint64_t
cass_uuid_timestamp(CassUuid uuid);

/**
 * Gets the version for a UUID
 *
 * @public @memberof CassUuid
 *
 * @param[in] uuid
 * @return The version of the UUID (1 or 4)
 */
CASS_EXPORT cass_uint8_t
cass_uuid_version(CassUuid uuid);

/**
 * Returns a null-terminated string for the specified UUID.
 *
 * @public @memberof CassUuid
 *
 * @param[in] uuid
 * @param[out] output A null-terminated string of length CASS_UUID_STRING_LENGTH.
 */
CASS_EXPORT void
cass_uuid_string(CassUuid uuid,
                 char* output);

/**
 * Returns a UUID for the specified string.
 *
 * Example: "550e8400-e29b-41d4-a716-446655440000"
 *
 * @public @memberof CassUuid
 *
 * @param[in] str
 * @param[out] output
 */
CASS_EXPORT CassError
cass_uuid_from_string(const char* str,
                      CassUuid* output);
/**
  * @see cass_uuid_from_string()
  */
CASS_EXPORT CassError
cass_uuid_from_string_n(const char* str,
                        size_t str_length,
                        CassUuid* output);

/***********************************************************************************
 *
 * Error
 *
 ***********************************************************************************/

/**
 * Gets a description for an error code.
 *
 * @param[in] error
 * @return A null-terminated string describing the error.
 */
CASS_EXPORT const char*
cass_error_desc(CassError error);

/***********************************************************************************
 *
 * Log
 *
 ***********************************************************************************/

/**
 * Explicitly wait for the log to flush and deallocate resources.
 * This *MUST* be the last call using the library. It is an error
 * to call any cass_*() functions after this call.
 */
void cass_log_cleanup();

/**
 * Sets the log level.
 *
 * Note: This needs to be done before any call that might log, such as
 * any of the cass_cluster_*() or cass_ssl_*() functions.
 *
 * Default: CASS_LOG_WARN
 *
 * @param[in] log_level
 */
CASS_EXPORT void
cass_log_set_level(CassLogLevel log_level);

/**
 * Sets a callback for handling logging events.
 *
 * Note: This needs to be done before any call that might log, such as
 * any of the cass_cluster_*() or cass_ssl_*() functions.
 *
 * Default: An internal callback that prints to stderr
 *
 * @param[in] data An opaque data object passed to the callback.
 * @param[in] callback A callback that handles logging events. This is
 * called in a separate thread so access to shared data must be synchronized.
 */
CASS_EXPORT void
cass_log_set_callback(CassLogCallback callback,
                      void* data);

/**
 * Sets the log queue size.
 *
 * Note: This needs to be done before any call that might log, such as
 * any of the cass_cluster_*() or cass_ssl_*() functions.
 *
 * Default: 2048
 *
 * @param[in] queue_size
 */
CASS_EXPORT void
cass_log_set_queue_size(size_t queue_size);

/**
 * Gets the string for a log level.
 *
 * @param[in] log_level
 * @return A null-terminated string for the log level.
 * Example: "ERROR", "WARN", "INFO", etc.
 */
CASS_EXPORT const char*
cass_log_level_string(CassLogLevel log_level);

/***********************************************************************************
 *
 * Inet
 *
 ************************************************************************************/

/**
 * Constructs an inet v4 object.
 *
 * @public @memberof CassInet
 *
 * @param[in] address An address of size CASS_INET_V4_LENGTH
 * @return An inet object.
 */
CASS_EXPORT CassInet
cass_inet_init_v4(const cass_uint8_t* address);

/**
 * Constructs an inet v6 object.
 *
 * @public @memberof CassInet
 *
 * @param[in] address An address of size CASS_INET_V6_LENGTH
 * @return An inet object.
 */
CASS_EXPORT CassInet
cass_inet_init_v6(const cass_uint8_t* address);

/**
 * Returns a null-terminated string for the specified inet.
 *
 * @public @memberof CassInet
 *
 * @param[in] inet
 * @param[out] output A null-terminated string of length CASS_INET_STRING_LENGTH.
 */
CASS_EXPORT void
cass_inet_string(CassInet inet,
                 char* output);

/**
 * Returns an inet for the specified string.
 *
 * Examples: "127.0.0.1" or "::1"
 *
 * @public @memberof CassInet
 *
 * @param[in] str
 * @param[out] output
 */
CASS_EXPORT CassError
cass_inet_from_string(const char* str,
                      CassInet* output);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __CASS_H_INCLUDED__ */
