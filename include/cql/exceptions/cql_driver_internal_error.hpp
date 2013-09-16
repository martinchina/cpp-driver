
/*
 * File:   cql_driver_internal_error.hpp
 * Author: mc
 *
 * Created on September 16, 2013, 9:53 AM
 */

#ifndef CQL_DRIVER_INTERNAL_ERROR_H_
#define	CQL_DRIVER_INTERNAL_ERROR_H_

#include "cql/exceptions/cql_exception.hpp"

namespace cql {
//  An unexpected error happened internally. This should never be raise and
//  indicates a bug (either in the driver or in Cassandra).
class cql_driver_internal_error: public cql_exception {
public:
    cql_driver_internal_error(const char* message)
        : cql_exception(message) { }
};
}

#endif	/* CQL_DRIVER_INTERNAL_ERROR_H_ */
