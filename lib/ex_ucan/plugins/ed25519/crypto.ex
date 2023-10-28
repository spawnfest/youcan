defmodule ExUcan.Plugins.Ed25519.Crypto do
  @moduledoc """
  Crypto functions related to `ExUcan.Plugins.Ed25519.Keypair`
  """
  alias ExUcan.Plugins.Utils

  @edwards_did_prefix <<0xED, 0x01>>

  # TODO: doc
  @spec did_to_publickey(did :: String.t()) :: binary()
  def did_to_publickey(did) do
    Utils.key_bytes_from_did(did, @edwards_did_prefix)
  end

  # TODO: doc
  @spec publickey_to_did(pubkey :: binary()) :: String.t()
  def publickey_to_did(pubkey) do
    Utils.did_from_key_bytes(pubkey, @edwards_did_prefix)
  end
end
