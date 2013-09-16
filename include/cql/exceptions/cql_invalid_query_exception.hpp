
/*
 * File:   cql_invalid_query_exception.hpp
 * Author: mc
 *
 * Created on September 16, 2013, 9:53 AM
 */

#ifndef CQL_INVALID_QUERY_EXCEPTION_H_
#define	CQL_INVALID_QUERY_EXCEPTION_H_

#include "cql/exceptions/cql_exception.hpp"

namespace cql {
class cql_invalid_query_exception: public cql_exception {
public:
    cql_invalid_query_exception(const char* message)
        : cql_exception(message) { }
};
}

#endif	/* CQL_INVALID_QUERY_EXCEPTION_H_ */
