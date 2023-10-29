defmodule ExUcan do
  @moduledoc """
  Documentation for `ExUcan`.
  """
  alias ExUcan.Keymaterial.Ed25519.Keypair
  alias ExUcan.Core.Token
  alias ExUcan.Core.Structs.Ucan

  @doc """
  Creates a default keypair with EdDSA algorithm

  This keypair can be later used for create UCAN tokens
  Keypair generated with different algorithms like RSA will be coming soon..
  """
  @spec create_default_keypair() :: Keypair.t()
  def create_default_keypair() do
    Keypair.create()
  end

  # TODO: to be removed
  @spec build(struct(), map()) :: {:ok, Ucan.t()} | {:error, String.t()}
  def build(keypair, _params) do
    Token.build(%{
      issuer: keypair,
      audience: "did:key:z6MkwDK3M4PxU1FqcSt4quXghquH1MoWXGzTrNkNWTSy2NLD",
      expiration: 86400
    })
  end

  # TODO: to be removed
  @spec encode(Ucan.t()) :: String.t()
  def encode(ucan) do
    Token.encode(ucan)
  end

  # TODO: Test this after Builder is setup
  @doc """
  Validate the UCAN token's signature and timestamps

  - encoded_token - Ucan token
  """
  @spec validate_token(String.t()) :: :ok | {:error, String.t()}
  def validate_token(encoded_token) do
    Token.validate(encoded_token)
  end
end
