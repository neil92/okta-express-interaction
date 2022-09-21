const express = require('express');
const router = express.Router();
const getAuthClient = require('./okta-transact/getAuthClient');
const handleTransaction = require('./okta-transact/handleTransaction');
const renderTemplate = require('./okta-transact/renderPage.js');
/* GET Login page.
router.get('/', function(req, res, next) {

});
*/

// entry route
router.get('/', async (req, res) => {
  req.setFlowStates({
    entry: '/login'
  });

  // Delete the idp related render logic if you only want the username and password form
  const authClient = getAuthClient(req);
  const tx = await authClient.idx.startTransaction({ state: req.transactionId });
  const { availableSteps, enabledFeatures } = tx;
  const idps = availableSteps
    ? availableSteps
      .filter(({ name }) => name === 'redirect-idp')
      .map(({ href, idp: { name }, type }) => ({
        name,
        href,
        class: getIdpSemanticClass(type),
        id: type.toLowerCase()
      }))
    : [];

  res.render('login', { title: 'Login' });
});

router.post('/', async (req, res, next) => {
  const { username, password } = req.body;
  const authClient = getAuthClient(req);
  const transaction = await authClient.idx.authenticate({
    username,
    password,
  });
  handleTransaction({ req, res, next, authClient, transaction });
});

router.get('/login/callback', async (req, res, next) => {
  const { protocol, originalUrl } = req;
  const parsedUrl = new URL(protocol + '://' + req.get('host') + originalUrl);
  const { search, href } = parsedUrl;
  const authClient = getAuthClient(req);

  try {
    if(hasErrorInUrl(search)) { 
      const error = new Error(`${req.query.error}: ${req.query.error_description}`);
      next(error);
      return;
    } 

    if (authClient.idx.isEmailVerifyCallback(search)) { 
      // may throw an EmailVerifyCallbackError if proceed is not possible
      const transaction = await authClient.idx.handleEmailVerifyCallback(search);
      handleTransaction({ req, res, next, authClient, transaction });
      return;
    } 

    if (authClient.idx.isInteractionRequired(search)) { 
      const error = new Error(
        'Multifactor Authentication and Social Identity Providers is not currently supported, Authentication failed.'  
      );
      next(error);
      return;
    } 

    // Exchange code for tokens
    await authClient.idx.handleInteractionCodeRedirect(href);
    // Redirect back to home page
    res.redirect('/');
  } catch (err) { 
    next(err);
  } 
});

module.exports = router;
