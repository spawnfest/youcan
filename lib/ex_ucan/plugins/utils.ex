defmodule ExUcan.Plugins.Utils do
  @moduledoc """
  Utilites related to plugins
  """

  @base58_did_prefix "did:key:z"

  # TODO: docs
  @spec did_from_key_bytes(publickey_bytes :: binary(), prefix :: binary()) :: String.t()
  def did_from_key_bytes(publickey_bytes, prefix) do
    bytes = <<prefix::binary, publickey_bytes::binary>>
    base58key = Base58.encode(bytes)
    @base58_did_prefix <> base58key
  end

  # TODO: docs
  @spec key_bytes_from_did(String.t(), binary()) :: {:ok, binary()} | {:error, String.t()}
  def key_bytes_from_did("did:key:z" <> non_prefix_did, expected_prefix) do
    bytes = Base58.decode(non_prefix_did)
    <<a::size(8), b::size(8), pub::binary>> = bytes

    if <<a, b>> == expected_prefix do
      {:ok, pub}
    else
      {:error, "Expected prefix #{inspect(expected_prefix)}"}
    end
  end

  def key_bytes_from_did(_did, _expected_prefix),
    do: {:error, "Please use a base58-encoded DID formatted `did:key:z..."}
end
