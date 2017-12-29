{-# LANGUAGE OverloadedStrings #-}
module Yesod.Auth.OAuth2.Github
    ( oauth2Github
    , defaultScopes
    ) where

import Yesod.Auth.OAuth2.Provider
import Yesod.Auth.OAuth2.UserId

oauth2Github :: ClientId -> ClientSecret -> [Scope] -> Provider m UserId
oauth2Github cid cs scopes = Provider
    { pName = "github"
    , pClientId = cid
    , pClientSecret = cs
    , pAuthorizeEndpoint = AuthorizeEndpoint
        $ "http://github.com/login/oauth/authorize" `withQuery`
            [ scopeParam "," scopes
            ]
    , pAccessTokenEndpoint = "http://github.com/login/oauth/access_token"
    , pFetchUserProfile = authGetProfile "https://api.github.com/user"
    , pParseUserProfile = eitherDecode
    , pUserProfileToIdent = userIdent
    }

defaultScopes :: [Scope]
defaultScopes = ["user:email"]
