{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Yesod.Auth.OAuth2.Dispatch
    ( dispatchAuthRequest
    ) where

import Control.Monad (unless)
import Data.Monoid ((<>))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Network.OAuth.OAuth2
import System.Random (newStdGen, randomRs)
import URI.ByteString.Extension
import Yesod.Auth
import Yesod.Auth.OAuth2.Provider
import Yesod.Core

-- | Dispatch the various OAuth2 handshake routes
dispatchAuthRequest :: Provider app a -> Text -> [Text] -> AuthHandler app TypedContent
dispatchAuthRequest p "GET" ["forward"] = dispatchForward p
dispatchAuthRequest p "GET" ["callback"] = dispatchCallback p
dispatchAuthRequest _ _ _ = notFound

-- | Handle @GET \/forward@
--
-- 1. Set a random CSRF token in our session
-- 2. Redirect to the Provider's authorization URL
--
dispatchForward :: Provider app a -> AuthHandler app TypedContent
dispatchForward p = do
    csrf <- setSessionCSRF $ tokenSessionKey p
    oauth2 <- providerToOAuth2 p csrf
    lift $ redirect $ toText $ authorizationUrl oauth2

-- | Handle @GET \/callback@
--
-- 1. Verify the URL's CSRF token matches our session
-- 2. Use the code parameter to fetch an AccessToken for the Provider
-- 3. Use the AccessToken to construct a @'Creds'@ value for the Provider
--
dispatchCallback :: Provider app a -> AuthHandler app TypedContent
dispatchCallback p = do
    csrf <- verifySessionCSRF $ tokenSessionKey p
    code <- requireGetParam "code"
    oauth2 <- providerToOAuth2 p csrf
    manager <- lift $ getsYesod authHttpManager
    token <- denyLeft $ fetchAccessToken manager oauth2 $ ExchangeToken code
    creds <- denyLeft $ providerCreds p manager token
    lift $ setCredsRedirect creds
  where
    -- On a Left result, log it and return an opaque permission-denied
    denyLeft :: (MonadHandler m, MonadLogger m, Show e) => IO (Either e a) -> m a
    denyLeft act = do
        result <- liftIO act
        either
            (\err -> do
                $(logError) $ T.pack $ "OAuth2 error: " <> show err
                permissionDenied "Invalid OAuth2 authentication attempt"
            )
            return
            result

-- | Convert our @'Provider'@ to an @'OAuth2'@ value
--
-- Append the CSRF token to the authorization URL as a state parameter.
--
providerToOAuth2 :: Provider app a -> Text -> AuthHandler app OAuth2
providerToOAuth2 Provider{..} csrfToken = do
    toParent <- getRouteToParent
    urlRender <- lift getUrlRender

    return OAuth2
        { oauthClientId = clientId pClientId
        , oauthClientSecret = clientSecret pClientSecret
        , oauthAccessTokenEndpoint = accessTokenEndpoint pAccessTokenEndpoint
        , oauthOAuthorizeEndpoint = authorizeEndpoint pAuthorizeEndpoint
            `withQuery` [("state", encodeUtf8 csrfToken)]
        , oauthCallback = Just
            $ unsafeFromText $ urlRender $ toParent
            $ PluginR (providerName pName) ["callback"]
        }

-- | Set a random, 30-character value in the session
setSessionCSRF :: MonadHandler m => Text -> m Text
setSessionCSRF sessionKey = do
    csrfToken <- liftIO randomToken
    csrfToken <$ setSession sessionKey csrfToken
  where
    randomToken = T.pack . take 30 . randomRs ('a', 'z') <$> newStdGen

-- | Verify the callback provided the same CSRF token as in our session
verifySessionCSRF :: MonadHandler m => Text -> m Text
verifySessionCSRF sessionKey = do
    token <- requireGetParam "state"
    sessionToken <- lookupSession sessionKey
    deleteSession sessionKey

    unless (sessionToken == Just token)
        $ permissionDenied "Invalid OAuth2 token"

    return token

requireGetParam :: MonadHandler m => Text -> m Text
requireGetParam key = do
    m <- lookupGetParam key
    maybe errInvalidArgs return m
  where
    errInvalidArgs = invalidArgs ["The '" <> key <> "' parameter is required"]

tokenSessionKey :: Provider m a -> Text
tokenSessionKey Provider{..} = "_yesod_oauth2_" <> providerName pName
