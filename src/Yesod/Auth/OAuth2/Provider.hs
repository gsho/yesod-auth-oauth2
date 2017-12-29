{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
module Yesod.Auth.OAuth2.Provider
    ( ClientId(..)
    , ClientSecret(..)
    , AuthorizeEndpoint(..)
    , AccessTokenEndpoint(..)
    , ProviderName(..)
    , Provider(..)
    , authGetProfile
    , eitherDecode
    , providerCreds
    , Scope(..)
    , scopeParam
    , withQuery
    ) where

import Control.Monad.Trans.Except
import Data.Aeson (eitherDecode)
import Data.Bifunctor (first)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (ByteString, toStrict)
import Data.String (IsString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Network.HTTP.Conduit (Manager)
import Network.OAuth.OAuth2
    (AccessToken(..), OAuth2Error(..), OAuth2Token(..), authGetBS)
import URI.ByteString (URI)
import URI.ByteString.Extension (withQuery)
import Yesod.Auth (Creds(..))

newtype ClientId = ClientId { clientId :: Text }
newtype ClientSecret = ClientSecret { clientSecret :: Text }

newtype AuthorizeEndpoint = AuthorizeEndpoint { authorizeEndpoint :: URI }
    deriving (IsString)

newtype AccessTokenEndpoint = AccessTokenEndpoint { accessTokenEndpoint :: URI }
    deriving (IsString)

newtype Scope = Scope { scope :: Text }
    deriving (IsString)

newtype ProviderName = ProviderName { providerName :: Text }
    deriving (IsString)

data Provider m a = Provider
    { pName :: ProviderName
    , pClientId :: ClientId
    , pClientSecret :: ClientSecret
    , pAuthorizeEndpoint :: AuthorizeEndpoint
    , pAccessTokenEndpoint :: AccessTokenEndpoint
    , pFetchUserProfile :: Manager -> AccessToken -> IO (Either Text ByteString)
    -- ^ Fetch an API response with user-identifying data
    --
    -- The response body will be parsed for their identifier and preserved as-is
    -- in @'credsExtra'@ as @userResponseBody@. See @'authGetProfile'@ as an
    -- example function for use in this field.
    --
    , pParseUserProfile :: ByteString -> Either String a
    -- ^ Parse the API response to a structured type
    --
    -- This will almost always be @'eitherDecode'@, i.e. parsing a JSON
    -- response into a domain module-local @UserId@ type using return-type
    -- polymorphism.
    --
    , pUserProfileToIdent :: a -> Text
    -- ^ Convert that type into the value for @'credsIdent'@
    }

authGetProfile :: URI -> Manager -> AccessToken -> IO (Either Text ByteString)
authGetProfile uri manager token =
    first prettyOAuth2Error <$> authGetBS manager token uri
  where
    prettyOAuth2Error :: OAuth2Error Text -> Text
    prettyOAuth2Error = T.pack . show -- FIXME

providerCreds :: Provider m a -> Manager -> OAuth2Token -> IO (Either Text (Creds m))
providerCreds Provider{..} manager token = runExceptT $ do
    lbs <- ExceptT $ pFetchUserProfile manager $ accessToken token
    user <- withExceptT T.pack $ ExceptT $ return $ pParseUserProfile lbs

    return Creds
        { credsPlugin = providerName pName
        , credsIdent = pUserProfileToIdent user
        , credsExtra =
            [ ("accessToken", atoken $ accessToken token)
            , ("userResponseBody", decodeUtf8 $ toStrict lbs)
            ]
        }

scopeParam :: Text -> [Scope] -> (BS.ByteString, BS.ByteString)
scopeParam d = ("scope",) . encodeUtf8 . T.intercalate d . map scope
