'use strict'

module.exports = {
  policies: {
    hasSession (sails, context) {
      return function hasSessionPolicy(req, res, next) {
        if(!req.headers.hasOwnProperty('authorization')) {
          sails.log.error('[Policies.hasSession] No Authorization header present')
          return res.error(new sails.AuthError('No authorization header present'))
        }

        if(req.headers.authorization.indexOf('Bearer ') === -1 || req.headers.authorization.split('Bearer ').length !== 2) {
          sails.log.error('[Policies.hasSession] Invalid Authorization header present')
          return res.error(new sails.AuthError('Invalid authorization header present'))
        }

        request({
          method: 'GET',
          url: `${sails.config.oauth.ssoUrl}/api/v1/me`,
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': req.headers.authorization
          },
          json: true
        }, (err, response, body) => {
          if(err) {
            sails.log.error('[Policies.hasSessipn] Error: ', err)
            return res.error(new sails.AuthError('Access token invalid'))
          }

          if(response.statusCode !== 200) {
            sails.log.error(`[Policies.hasSession] Invalid statusCode (${response.statusCode})`)
            return res.error(new sails.AuthError('Access token invalid'))
          }

          if(body === null || typeof body !== 'object') {
            sails.log.error('[Policies.hasSession] Invalid response from SSO')
            return res.error(new sails.AuthError('Invalid response from SSO'))
          }

          req.user = body

          return next()
        })

      }.bind(context)
    },
  },

  responses: {
    error (data) {
      // Get access to `req`, `res`, & `sails`
      const req = this.req
      var res = this.res
      let toReturn

      if(!_.isObject(data) && !_.isArray(data)) {
        // Set status code
        res.status(400)
        toReturn = {
          code: "E_ERROR",
          message: data
        }
      } else {
        res.status(500)
      }
      if(!_.isArray(data) && _.isObject(data)) {
        if(data.hasOwnProperty('originalError') && data.originalError.hasOwnProperty('message') && data.originalError.hasOwnProperty('code')) {
          toReturn = {
            code: data.originalError.code,
            status: data.statusCode,
            message: data.originalError.message,
            stack: data.rawStack
          }
        } else {
          if(data.hasOwnProperty('status')) {
            res.status(data.status)
          }
          toReturn = {
            code: data.code,
            status: data.status,
            message: data.message
          }
        }
      }
      return res.jsonx(toReturn)
    },

    success (data, options) {
      let req = this.req;
      let res = this.res;

      res.status(200);

      let toReturn = {};
      let url = req.url;
      if(!Array.isArray(data)) {
        toReturn = data;
      } else {
        const skip = req.param('skip') || 0
        const limit = req.param('limit') || 250
        if(url.indexOf('limit='+limit) === -1) {
          url += '&limit='+limit
        }
        if(url.indexOf('skip=') === -1) {
          url += '&skip='+skip
        }
        toReturn = {
          skip: parseInt(skip),
          limit: parseInt(limit)
        }
        if(data.length > 0) {
          if(skip > 0) {
            let temp = url;
            let newSkip = skip;
            if(data.length < limit) {
              newSkip = skip-limit;
            }
            if(newSkip < 0) {
              newSkip = skip-data.length;
            }
            if(newSkip < limit || newSkip < 0) {
              newSkip = 0;
            }
            toReturn.previous = temp.replace('skip='+skip, 'skip='+newSkip)
          }
          if(!(data.length < limit)) {
            let temp = url;
            let newSkip = parseInt(skip)+parseInt(data.length);
            toReturn.next = temp.replace('skip='+skip, 'skip='+newSkip)
          }
        }
        toReturn.results = data;
      }

      return res.jsonx(toReturn);
    },
  },

  prefixRoutes (routes) {
    let toReturn = {};

    if(typeof process.env.PATH_PREFIX === 'undefined' || (typeof process.env.PATH_PREFIX === 'string' && (process.env.PATH_PREFIX.trim().length === 0) || !process.env.PATH_PREFIX.trim().includes('/'))) {
      return routes
    }

    console.log(`[Bootstrap.routes] Using pathPrefix ${process.env.PATH_PREFIX}`)

    Object.keys(routes).forEach((key, index) => {
      let splitKey = key.split(' ');
      toReturn[`${splitKey[0]} ${process.env.PATH_PREFIX}${splitKey[1]}`] = routes[key]
      if(splitKey[1] === '/') {
        toReturn[`${splitKey[0]} ${process.env.PATH_PREFIX}`] = routes[key]
      }
    })

    return toReturn
  },

  createEnvService (sails, required) {
    return {
      validate(cb) {
        sails.log.info(`[EnvService.${process.env.NODE_ENV}] Validating`)
        let failed = false;
        Object.keys(required[process.env.NODE_ENV]).forEach(key => {
          if(!process.env.hasOwnProperty(key)) {
            sails.log.error('[EnvService] Missing Key: ' + key + '')
            failed = true;
          } else {
            if(required[process.env.NODE_ENV][key] === 'number') {
              if(isNaN(parseInt(process.env[key]))) {
                sails.log.error('[EnvService.] Key ' + key + ' incorrect type: ' + typeof process.env[key] + ', should be ' + required[process.env.NODE_ENV][key])
                failed = true;
              }
            } else if(typeof process.env[key] !== required[process.env.NODE_ENV][key]) {
              sails.log.error('[EnvService] Key ' + key + ' incorrect type: ' + typeof process.env[key] + ', should be ' + required[process.env.NODE_ENV][key])
              failed = true;
            }
          }
        })

        if(failed) {
          sails.log.error(`[EnvService.${process.env.NODE_ENV}] Environment Invalid, Exiting`)
          if(typeof cb === 'function') {
            cb(false)
          } else {
            process.exit(1)
          }
        } else {
          sails.log.info(`[EnvService.${process.env.NODE_ENV}] Environment Valid, Continuing`)
          if(typeof cb === 'function') {
            cb(true)
          }
        }
      }
    }
  },

  populateCustomErrors (sails) {
    function ValidationError(message) {
      this.name = 'ValidationError';
      this.message = message;
      this.code = 'E_VALIDATION';
      this.stack = (new Error()).stack;
    }
    ValidationError.prototype = new Error;
    sails.ValidationError = ValidationError;

    function AuthError(message) {
      this.name = 'AuthError';
      this.message = message;
      this.code = 'E_AUTH';
      this.status = 403;
      this.stack = (new Error()).stack;
    }
    AuthError.prototype = new Error;
    sails.AuthError = AuthError;

    function ServerError(message) {
      this.name = 'ServerError';
      this.message = message;
      this.code = 'E_SERVER';
      this.stack = (new Error()).stack;
      this.status = 500;
    }
    ServerError.prototype = new Error;
    sails.ServerError = ServerError;

    function RequestError(message) {
      this.name = 'RequestError';
      this.message = message;
      this.code = 'E_REQUEST';
      this.stack = (new Error()).stack;
      this.status = 400;
    }
    RequestError.prototype = new Error;
    sails.RequestError = RequestError;

    function NotFoundError(message) {
      this.name = 'NotFoundError';
      this.message = message;
      this.code = 'E_NOTFOUND';
      this.stack = (new Error()).stack;
      this.status = 404;
    }
    NotFoundError.prototype = new Error;
    sails.NotFoundError = NotFoundError;
  },
}
