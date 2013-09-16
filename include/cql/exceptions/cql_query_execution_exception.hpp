
/*
 * File:   cql_query_execution_exception.hpp
 * Author: mc
 *
 * Created on September 16, 2013, 9:53 AM
 */

#ifndef CQL_QUERY_EXECUTION_EXCEPTION_H_
#define	CQL_QUERY_EXECUTION_EXCEPTION_H_

#include "cql/exceptions/cql_exception.hpp"

namespace cql {
class cql_query_execution_exception: public cql_exception {
public:
    cql_query_execution_exception(const char* message)
        : cql_exception(message) { }
};
}

#endif	/* CQL_QUERY_EXECUTION_EXCEPTION_H_ */
