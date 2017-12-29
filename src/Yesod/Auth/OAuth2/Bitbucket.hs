{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.OAuth2.Bitbucket
    ( oauth2Bitbucket
    ) where

import Data.Aeson
import Data.Text (Text)
import Yesod.Auth.OAuth2.Provider

newtype UserId = UserId { userId :: Text }

instance FromJSON UserId where
    parseJSON = withObject "User" $ \o -> UserId <$> o .: "uuid"

oauth2Bitbucket :: ClientId -> ClientSecret -> [Scope] -> Provider m UserId
oauth2Bitbucket cid cs scopes = Provider
    { pName = "bitbucket"
    , pClientId = cid
    , pClientSecret = cs
    , pAuthorizeEndpoint = AuthorizeEndpoint
        $ "https://bitbucket.com/site/oauth2/authorize" `withQuery`
            [ scopeParam "," scopes
            ]
    , pAccessTokenEndpoint = "https://bitbucket.com/site/oauth2/access_token"
    , pFetchUserProfile = authGetProfile "https://api.bitbucket.com/2.0/user"
    , pParseUserProfile = eitherDecode
    , pUserProfileToIdent = userId
    }
