/**
 * @file sr_error.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo error definitions.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SRC_SR_ERROR_H_
#define SRC_SR_ERROR_H_

/**
 * @brief Sysrepo error codes.
 */
typedef enum sr_error_e {
    SR_ERR_OK = 0,       /**< No error. */
    SR_ERR_INVAL_ARG,    /**< Invalid argument. */
    SR_ERR_NOMEM,        /**< Not enough memory. */
    SR_ERR_NOT_FOUND,    /**< Item not found. */
    SR_ERR_INTERNAL,     /**< Other internal error. */
    SR_ERR_INIT_FAILED,  /**< Sysrepo infra initailization failed. */
} sr_error_t;

#endif /* SRC_SR_ERROR_H_ */
