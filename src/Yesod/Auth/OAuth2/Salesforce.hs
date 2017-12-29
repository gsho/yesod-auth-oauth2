{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.OAuth2.Salesforce
    ( oauth2Salesforce
    , oauth2SalesforceSandbox
    , defaultScopes
    ) where

import Data.Aeson
import Data.Text (Text)
import Yesod.Auth.OAuth2.Provider

newtype UserId = UserId { userId :: Text }

instance FromJSON UserId where
    parseJSON = withObject "User" $ \o -> UserId <$> o .: "user_id"

oauth2Salesforce :: ClientId -> ClientSecret -> [Scope] -> Provider m UserId
oauth2Salesforce cid cs scopes = Provider
    { pName = "salesforce"
    , pClientId = cid
    , pClientSecret = cs
    , pAuthorizeEndpoint = AuthorizeEndpoint
        $ "https://login.salesforce.com/services/oauth2/authorize" `withQuery`
            [ scopeParam " " scopes
            ]
    , pAccessTokenEndpoint = "https://login.salesforce.com/services/oauth2/token"
    , pFetchUserProfile = authGetProfile "https://login.salesforce.com/services/oauth2/userinfo"
    , pParseUserProfile = eitherDecode
    , pUserProfileToIdent = userId
    }

oauth2SalesforceSandbox :: ClientId -> ClientSecret -> [Scope] -> Provider m UserId
oauth2SalesforceSandbox cid cs scopes = Provider
    { pName = "salesforce-sandbox"
    , pClientId = cid
    , pClientSecret = cs
    , pAuthorizeEndpoint = AuthorizeEndpoint
        $ "https://test.salesforce.com/services/oauth2/authorize" `withQuery`
            [ scopeParam " " scopes
            ]
    , pAccessTokenEndpoint = "https://test.salesforce.com/services/oauth2/token"
    , pFetchUserProfile = authGetProfile "https://test.salesforce.com/services/oauth2/userinfo"
    , pParseUserProfile = eitherDecode
    , pUserProfileToIdent = userId
    }

defaultScopes :: [Scope]
defaultScopes = ["openid", "email", "api"]
