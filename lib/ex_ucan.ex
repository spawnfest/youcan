defmodule ExUcan do
  @moduledoc """
  Documentation for `ExUcan`.
  """
  alias ExUcan.Plugins.Ed25519
  alias ExUcan.Core.Token
  alias ExUcan.Core.Structs.Ucan

  def create_keypair() do
    Ed25519.Keypair.create()
  end

  @spec build(struct(), map()) :: {:ok, Ucan.t()} | {:error, String.t()}
  def build(keypair, _params) do
    Token.build(%{
      issuer: keypair,
      audience: "did:key:z6MkwDK3M4PxU1FqcSt4quXghquH1MoWXGzTrNkNWTSy2NLD",
      expiration: 86400
    })
  end

  @spec encode(Ucan.t()) :: String.t()
  def encode(ucan) do
    Token.encode(ucan)
  end
end
