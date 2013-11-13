/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

var loginApi = require( "./loginapi" );

module.exports = function( makeModel, apiUserModel, env ) {
  var qs = require( "querystring" ),
      hawkModule = require( "./hawk" )(),
      tags = require( "./tags" )(),
      logger = require('./logger'),
      Make = makeModel,
      hawkOptions = {},
      credentialsLookupStrategy = require( "./strategy" )( apiUserModel, env.get( "USE_DEV_KEY_LOOKUP" ) );

  // fields that collaborator accounts can update
  var COLLABORATOR_FIELDS = [
    "tags"
  ];

  if ( env.get( "FORCE_SSL" ) ) {
    hawkOptions.port = 443;
  }


  function doesUserLike( id, likes ) {
    var like,
        i;
    for ( i = likes.length - 1; i >= 0; i-- ) {
      like = likes[ i ];
      if ( like.userId === id ) {
        return like;
      }
    }
    return null;
  }
  
  /*
   *used to check for blackisted words
   **/
  function checkfilter(data){
      if (typeof data !== "string") {
        data = (data || "").toString();
      }
      var blacklist = {};
      var blacklist_words = ['ass','arse', 'arsehole', 'assbag', 'assbandit','assbanger', 'assbite', 'assclown',
                   'asscock', 'assface', 'asshat', 'asshead', 'asshole', 'asshopper', 'assjacker',
                   'asslicker', 'assmunch', 'assshole', 'asswipe', 'bampot', 'bastard', 'beaner',
                   'bitch', 'bitchass', 'bitchy', 'blow job', 'blowjob', 'boner', 'bullshit', 'butt plug',
                   'butt-pirate', 'camel toe', 'carpetmuncher', 'chinc', 'chink', 'choad', 'chode', 'clit',
                   'cock', 'cockbite', 'cockface','cockmaster', 'cockmongruel', 'cockmuncher', 'cocksmoker',
                   'cocksucker', 'coochie', 'coon', 'cooter', 'cracker', 'cum', 'cumbubble', 'cumtart',
                   'cunnilingus', 'cunt', 'cunthole', 'damn', 'deggo', 'dick', 'dickbag', 'dickhead',
                   'dickhole', 'dickmonger', 'dicks', 'dickweed', 'dickwod', 'dildo', 'dipshit', 'dookie',
                   'douche', 'douchebag', 'douchewaffle', 'dumass', 'dumb ass', 'dumbass', 'dumbshit',
                   'dumshit', 'dyke', 'fag', 'fagbag', 'faggit', 'faggot', 'fagtard', 'fatass', 'fellatio', 'fuck',
                   'fudgepacker', 'gaydo', 'gaytard', 'gaywad', 'goddamn', 'goddamnit', 'gooch', 'gook',
                   'gringo', 'guido', 'handjob', 'hard on', 'heeb', 'hell', 'ho', 'homo', 'homodumbshit',
                   'honkey', 'humping', 'jackass', 'jap', 'jerk off', 'jigaboo', 'jizz', 'jungle bunny',
                   'kike', 'kooch', 'kootch', 'kyke','lesbo', 'lezzie', 'mcfagget', 'mick', 'minge', 'muff',
                   'munging', 'negro', 'nigga', 'nigger', 'niglet', 'nut sack', 'nutsack', 'paki', 'panooch',
                   'pecker', 'peckerhead', 'penis', 'piss', 'pissed', 'pissed off', 'pollock', 'poon', 'poonani',
                   'poonany', 'porch monkey', 'porchmonkey', 'prick', 'punta', 'pussy', 'pussylicking', 'puto',
                   'queef', 'queer', 'queerbait', 'renob', 'rimjob', 'sand nigger', 'sandnigger', 'schlong',
                   'scrote', 'shit', 'shitbagger', 'shitcunt', 'shitdick', 'shitface', 'shitfaced', 'shithead',
                   'shitter', 'shittiest', 'shitting', 'shitty', 'skank', 'skeet', 'slut', 'slutbag', 'snatch',
                   'spic', 'spick', 'splooge', 'tard', 'testicle', 'thundercunt', 'tit', 'tits', 'twat', 'twatlips',
                   'twats', 'twatwaffle', 'va-j-j', 'vag', 'vjayjay', 'wank', 'wetback', 'whore', 'whorebag',
                   'wop'];
     
      blacklist = new RegExp("(" + blacklist_words.join(" | ") + ")", "ig");
      if (data.match(blacklist)) {
       //found  
        return 1;
      }
      //not found
      return 0;
  }

  return {
    prefixAuth: function( req, res, next ) {

      // Support older POST body formats for Makes
      if ( req.body.maker && req.body.make ) {
        req.body = req.body.make;
      }

      var email = req.body.email,
          makeTags = req.body.tags,
          appTags = req.body.appTags,
          make = req.make;

      makeTags = typeof makeTags === "string" ? [makeTags] : makeTags;
      appTags = typeof appTags === "string" ? [appTags] : appTags;

      loginApi.getUserByEmail( email, function( err, user ) {
        if ( err ) {
          return hawkModule.respond( 500, res, req.credentials, req.artifacts, { status: "failure", reason: err }, "application/json" );
        }
        if ( !user ) {
          return hawkModule.respond( 400, res, req.credentials, req.artifacts, { status: "failure", reason: "User does not exist" }, "application/json" );
        }

        var options = {
              maker: email,
              isAdmin: user.isAdmin
            },
            validTags = [];

        if ( makeTags ) {
           validTags = tags.validateTags( makeTags, options );
         }

        if ( appTags ) {
          validTags = validTags.concat( tags.validateApplicationTags( appTags, req.user ) );
        }

        // Preserve Application Tags on the original make & filter duplicates
        if ( make && make.tags ) {
          validTags = validTags.concat( make.tags.filter(function( tag ) {
            return ( /(^[^@]+)\:[^:]+/ ).test( tag );
          })).filter(function( tag, pos, arr ) {
            return arr.indexOf( tag ) === pos;
          });
        }

        req.body.tags = validTags;

        next();
      });
    }, blacklistedCheck: function(req, res, next){
      
            // Support older POST body formats for Makes
      if ( req.body.maker && req.body.make ) {
        req.body = req.body.make;
      }
      //checks tags backlist words
      var tagOriginal = req.body.tags;
      //checks description backlist words 
      var desOriginal = req.body.description;
      var countBad = 0;
      //runs to filter
      countBad += checkfilter(tagOriginal);
      countBad += checkfilter(desOriginal);

      if (countBad != 0) {
      console.log("***********found**************");
         return next(new Error(req.gettext("blacklisted word was found")));
      }
      next();
    },
    adminAuth: function( req, res, next ) {
      var id = req.session ? req.session.id : "";
      if ( id ) {
        loginApi.getUserById( id, function( err, user ) {
          if ( err ) {
            return next( err );
          }
          if ( !user || !user.isAdmin ) {
            return res.redirect( 302, "/login" );
          }
          next();
        });
      } else {
        res.redirect( 302, "/login" );
      }
    },
    collabAuth: function( req, res, next ) {
      var id = req.session ? req.session.id : "";
      if ( id ) {
        loginApi.getUserById( id, function( err, user ) {
          if ( err ) {
            return next( err );
          }
          if ( !user.isCollaborator && !user.isAdmin ) {
            return res.redirect( 302, "/login" );
          }
          req.isCollab = user.isCollaborator;
          next();
        });
      } else {
        res.redirect( 302, "/login" );
      }
    },
    hawkAuth: function( req, res, next ) {
      hawkModule.Hawk.server.authenticate( req, credentialsLookupStrategy, hawkOptions, function( err, creds, artifacts ) {
        var msg;
        if ( err || req.revokedKey ) {
          msg = err ? err.message : "Your Key has been revoked, contact a MakeAPI administrator.";
          return hawkModule.respond( 401, res, creds, artifacts, { status: "failure", reason: msg }, "application/json" );
        }
        req.credentials = creds;
        req.artifacts = artifacts;
        next();
      });
    },
    getMake: function( req, res, next ) {
      if ( !req.params.id ) {
        return hawkModule.respond( 400, res, req.credentials, req.artifacts, { status: "failure", reason: "ID missing" }, "application/json" );
      }
      Make.findById( req.params.id ).where( "deletedAt", null ).exec(function( err, make ) {
        if ( err ) {
          if ( err.name === "CastError" ) {
            return hawkModule.respond( 400, res, req.credentials, req.artifacts, { status: "failure", reason: "The supplied value does not look like a Make ID." }, "application/json" );
          } else {
            return hawkModule.respond( 500, res, req.credentials, req.artifacts, { status: "failure", reason: err.toString() }, "application/json" );
          }
        }
        if ( !make ) {
          return hawkModule.respond( 400, res, req.credentials, req.artifacts, { status: "failure", reason: "Make Does Not Exist" }, "application/json" );
        }
        req.make = make;
        next();
      });
    },
    fieldFilter: function( req, res, next ) {
      var sanitizedUpdate = {};
      if ( req.isCollab ) {
        COLLABORATOR_FIELDS.forEach(function( safeField ) {
          sanitizedUpdate[ safeField ] = req.body[ safeField ];
        });
        req.body = sanitizedUpdate;
      }
      next();
    },
    like: function( req, res, next ) {
      var make = req.make;
      loginApi.getUserByUsername( req.body.maker, function( err, user ) {
        if ( err ) {
          return next( err );
        }
        var userLike = doesUserLike( user.id, make.likes );
        if ( !userLike ) {
          make.likes.push({
            userId: user.id
          });
          next();
        } else {
          next({
            status: 400,
            message: "User already Likes"
          });
        }
      });
    },
    unlike: function( req, res, next ) {
      var make = req.make;
      loginApi.getUserByUsername( req.body.maker, function( err, user ) {
        if ( err ) {
          return next( err );
        }
        var userLike = doesUserLike( user.id, make.likes );
        if ( userLike ) {
          make.likes.splice( make.likes.indexOf( userLike ), 1 );
          next();
        } else {
          next({
            status: 400,
            message: "User does not like"
          });
        }
      });
    },
    crossOrigin: function( req, res, next ) {
      res.header( "Access-Control-Allow-Origin", "*" );
      next();
    },
    errorHandler: function(err, req, res, next) {
      if (!err.status) {
        err.status = 500;
      }

      res.status(err.status);
      res.json(err);
    },
    fourOhFourHandler: function(req, res, next) {
      var err = {
        message: "You found a loose thread!",
        status: 404
      };

      res.status(err.status);
      res.json(err);
    }
  };
};
