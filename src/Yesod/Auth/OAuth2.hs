{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}
module Yesod.Auth.OAuth2
    ( oauth2Url
    , authOAuth2
    ) where

import Yesod.Auth
import Yesod.Auth.OAuth2.Dispatch
import Yesod.Auth.OAuth2.Provider
import Yesod.Core (WidgetT, whamlet)

-- | Login route for a provider by name
oauth2Url :: ProviderName -> AuthRoute
oauth2Url (ProviderName name) = PluginR name ["forward"]

-- | Yesod Auth Plugin for a given Provider
--
-- Example:
--
-- > import Yesod.Auth.OAuth2
-- > import Yesod.Auth.OAuth2.Github
-- >
-- > authOAuth2 $ oauth2Github "CLIENT_ID" "CLIENT_SECRET" defaultScopes
--
authOAuth2 :: YesodAuth m => Provider m a -> AuthPlugin m
authOAuth2 = authOAuth2Widget $ \name toParent ->
    [whamlet|
        <a href=@{toParent $ oauth2Url name}>
            Login via #{providerName name}
    |]

-- | Same, but with custom login Widget
--
-- > import Yesod.Auth.OAuth2
-- > import Yesod.Auth.OAuth2.Github
-- >
-- > authOAuth2Widget
-- >     (\name toParent ->
-- >         [whamlet|
-- >             <a href=@{toParent $ oauth2Url name}>
-- >                 Login via #{providerName name}
-- >         |]
-- >     )
-- >     $ oauth2Github -- ...
--
authOAuth2Widget
    :: YesodAuth m
    => (ProviderName -> (Route Auth -> Route m) -> WidgetT m IO ())
    -> Provider m a
    -> AuthPlugin m
authOAuth2Widget widget p@Provider{..} =
    AuthPlugin (providerName pName) (dispatchAuthRequest p) $ widget pName
