const http = Meteor.npmRequire('http');
const url = Meteor.npmRequire('url');
const parseXML      = Meteor.npmRequire('xml2js').parseString,
      XMLprocessors = Meteor.npmRequire('xml2js/lib/processors');

const casSettings = Meteor.customMethods.getSetting(['cas']).cas;

const serverHost = casSettings.serverHost,
      serverPort = casSettings.serverPort,
      serverLoginURL = casSettings.serverLoginURL,
      serverLogoutURL = casSettings.serverLogoutURL,
      serverVailidateTicket = casSettings.serverVailidateTicket,
      serviceUrl = casSettings.serviceUrl;
var casTicket = new Mongo.Collection('cas_ticket');
var userTokens = new Mongo.Collection('user_token');

var globalUser;

/*
 * 注册登录处理函数
 */
Accounts.registerLoginHandler(function(loginRequest) {
  if (CryptoJS.AES.decrypt(loginRequest.token, 'key').toString(CryptoJS.enc.Utf8) !== 'cas') {
    return undefined;
  }
  var username, userToken = userTokens.findOne({token: token});
  if (!userToken || !userToken.username) {
    return undefined;
  } else {
    username = userToken.username;
  }
  var userId, user = Meteor.users.findOne({'emails.address': globalUser});
  if(!user) {
    userId = Meteor.users.insert({
      username: globalUser,
      createdAt: new Date(),
      emails: [{ address: globalUser, verified: false}],
      profile: {}
    });
  } else {
    userId = user._id;
  }
  return {userId: userId};
});

// 处理cas client登录和cas server 发送的登出请求
WebApp.connectHandlers.use("/accounts/login", login);
// 处理应用的登出请求
WebApp.connectHandlers.use("/accounts/logout", logout);

function logout(req, res, next) {
  let logoutURL = casSettings.serverLogoutURL +
    url.format({query: {url: casSettings.clientURL}});
  res.writeHead(302, {location: logoutURL});
  res.end();
}



function login(req, res, next) {
  if (req.method === 'POST') {
    // server 请求登出
    var logoutBody= '';
    req.on('data', function(chunk) {
      return logoutBody += chunk;
    });
    req.on('end', function() {
      _parseXMLToLogout(logoutBody, function(err, ticket) {
        if (err) {
          res.writeHead(401);
          console.log('parse xml to logout error: ' + errerr);
          res.end('parse xml to logout error: ' + err);
        } else {
          var ticketData = casTicket.findOne({'ticket': ticket});
          if (ticketData) {
            Meteor.users.update({username: ticketData.username}, {$set: {"services.resume.loginTokens": []}});
          }
          res.end();
        }
      });
    });
    req.on('error', function(err) {
      console.log('Logout request error from CAS server : ', err);
      res.writeHead(401);
      res.end(err);
    });
  }

  if (req.query.ticket) {
    //cas服务端请求cas客户端，ticket校验，获取用户信息
    var requestOpt = {
      host: serverHost,
      port: serverPort,
      method: 'GET',
      path: url.format({
        pathname: serverVailidateTicket,
        query: { service: serviceUrl, ticket: req.query.ticket }
      })
    };

    var request = http.request(requestOpt, function(response) {
      response.setEncoding('utf8');
      var body = '';

      response.on('data', function(chunk) {
          return body += chunk;
      }.bind(this));

      response.on('end', function() {
        _parseXMLToGetUser(body, function(err, user, attributes) {
          if (err) {
            res.writeHead(401);
            res.end('parse xml to get user error from CAS server: ' + err);
          } else {
            // 存储用户的ticket服务器登出请求使用
            casTicket.upsert({username: user}, {$set: {ticket: req.query.ticket}});
            // 生成token和用户绑定。携带token重定向到前端路由，前端调用登录方法
            var token = CryptoJS.AES.encrypt('cas', 'key').toString();
            userTokens.upsert({username: user}, {$set: {token: token}});

            var clientLoginURL = casSettings.clientLoginURL + url.format({query: {token: token}});
            res.writeHead('302', { location: clientLoginURL });
            res.end();
          }
        }.bind(this));
      }.bind(this));

      response.on('error', function(err) {
          console.log('Login response error from CAS server: ', err);
          res.writeHead(401);
          res.end('Login response error from CAS server: ', err);
      }.bind(this));

    });

    request.on('error', function(err) {
      console.log('Request error with CAS: ', err);
      res.writeHead(401);
      res.end('Request error with CAS: ', err);
    });
    request.end();
  } else{
    //用户请求登录链接
    var location = casSettings.serverLoginURL + url.format({query: { service: serviceUrl }});
    res.writeHead(302, { location: location });
    res.end();
  }
}

/*
 * 获取用户信息函数
 * @param {string} xml文本
 * @callback {func} 回调函数
 */
var _parseXMLToGetUser = Meteor.bindEnvironment(function(body, callback) {
  parseXML(body, {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [ XMLprocessors.normalize, XMLprocessors.stripPrefix ]
  }, function(err, result) {
    if (err) {
      return callback(new Error('Response from CAS server was bad.'));
    }
    try {
      var failure = result.serviceresponse.authenticationfailure;
      if (failure) {
        return callback(new Error('CAS authentication failed (' + failure.$.code + ').'));
      }
      var success = result.serviceresponse.authenticationsuccess;
      if (success) {
        return callback(null, success.user, success.attributes);
      }
      else {
        return callback(new Error( 'CAS authentication failed (Has no user info).'));
      }
    }
    catch (err) {
      console.log(err);
      return callback(new Error('CAS authentication failed (' + err + ').'));
    }
  });
});

/*
 * 获取通行证登出请求传递的ticket参数
 * @param {string} xml文本
 * @cb {func} 回调函数
 */
var _parseXMLToLogout = Meteor.bindEnvironment(function(body, cb) {
  parseXML(body, {
    trim: true,
    normalize: true,
    explicitArray: false,
    tagNameProcessors: [ XMLprocessors.normalize, XMLprocessors.stripPrefix ]
  }, function(err, result) {
    if (err) {
      return cb(new Error('Logout from CAS Server failed(' + err + ').'));
    }
    try {
      var ticket = result.logoutrequest.sessionindex;
      if (ticket) {
        return cb(null, ticket);
      } else{
        return cb(new Error('Logout from CAS Server failed(no logout ticket from server).'));
      }
    } catch (error) {
      return cb(new Error('Logout from CAS Server failed(' + error + ').'));
    }
  });
});

