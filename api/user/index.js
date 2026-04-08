const { getClientPrincipal } = require('../shared/auth');

module.exports = async function (context, req) {
  return {
    status: 200,
    body: {
      clientPrincipal: getClientPrincipal(req)
    }
  };
};
