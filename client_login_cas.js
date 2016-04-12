angular.module('angle').controller('loginCasCtrl', ["$scope", "$meteor", "$stateParams", "$state",
  function ($scope, $meteor, $stateParams, $state) {
    let token = $stateParams.token;
    if (CryptoJS.AES.decrypt(token, 'key').toString(CryptoJS.enc.Utf8) === 'cas') {
      let loginRequest = {token: token};
      Accounts.callLoginMethod({
        methodArguments: [loginRequest],
      });
    } else {
      $notify.danger('登录验证失败。');
    }
  }
]);

