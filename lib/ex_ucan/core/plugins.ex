defmodule ExUcan.Core.Plugins do
  alias ExUcan.Plugins.Ed25519.Crypto
  # TODO: docs

  @spec verify_issuer_alg(String.t(), String.t()) :: boolean()
  def verify_issuer_alg(did, jwt_alg) do
  end

  @spec verify_signature(String.t(), String.t(), String.t()) :: boolean()
  def verify_signature(did, data, signature) do
    {:ok, public_key} = Crypto.did_to_publickey(did)
    IO.inspect(public_key)
    IO.inspect(data)
    IO.inspect(signature)
    :public_key.verify(data, :ignored, signature, {:ed_pub, :ed25519, public_key})
  end

  @spec parseDidMethod(String.t()) :: String.t()
  defp parseDidMethod(did) do
    parts = String.split(did, ":")

    with {true, _} <- {Enum.at(parts, 0) == "did", 0},
         {true, _} <- {String.length(Enum.at(parts, 1)) >= 1, 1} do
      {:ok, Enum.at(parts, 2)}
    else
      {false, 0} -> {:error, "Not a DID: #{did}"}
      {false, 1} -> {:error, "No DID method included: #{did}"}
    end
  end
end
