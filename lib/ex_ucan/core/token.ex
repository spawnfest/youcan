defmodule ExUcan.Core.Token do
  @moduledoc """
  Creates and manages UCAN tokens
  """
  alias ExUcan.Keymaterial.Ed25519.Crypto
  alias ExUcan.Core.Structs.UcanHeader
  alias ExUcan.Keymaterial
  alias ExUcan.Core.Structs.Ucan
  alias ExUcan.Core.Utils
  alias ExUcan.Core.Structs.UcanPayload

  @token_type "JWT"
  @version %{major: 0, minor: 10, patch: 0}

  @spec build(
          params :: %{
            issuer: struct(),
            audience: String.t(),
            # Add capabilities struct later
            capabilities: list(),
            life_time_in_seconds: number(),
            expiration: number(),
            not_before: number(),
            # Add Facts struct later
            facts: list(),
            proofs: list(String.t()),
            add_nonce?: boolean()
          }
        ) :: Ucan.t()
  def build(params) do
    {:ok, payload} = build_payload(%{params | issuer: Keymaterial.did(params.issuer)})
    sign_with_payload(payload, params.issuer)
  end

  # TODO: docs
  @spec build_payload(
          params :: %{
            issuer: String.t(),
            audience: String.t(),
            # Add capabilities struct later
            capabilities: list(),
            life_time_in_seconds: number(),
            expiration: number(),
            not_before: number(),
            # Add Facts struct later
            facts: list(),
            proofs: list(String.t()),
            add_nonce?: boolean()
          }
        ) :: UcanPayload.t()
  def build_payload(params) do
    with {:iss, true} <- {:iss, String.starts_with?(params.issuer, "did")},
         {:aud, true} <- {:aud, String.starts_with?(params.audience, "did")} do
      current_time_in_seconds = DateTime.utc_now() |> DateTime.to_unix()
      exp = params.expiration || current_time_in_seconds + params.life_time_in_seconds

      {:ok,
       %{
         ucv: "#{@version.major}.#{@version.minor}.#{@version.patch}",
         iss: params.issuer,
         aud: params.audience,
         nbf: params[:not_before] || nil,
         exp: exp,
         nnc: add_nonce(params[:add_nonce] || false),
         fct: params[:facts] || [],
         cap: params[:capabilities] || [],
         prf: params[:proofs] || []
       }}
    else
      {:iss, false} -> {:error, "The issuer must be a DID"}
      {:aud, false} -> {:error, "The audience must be a DID"}
    end
  end

  @spec encode(Ucan.t()) :: String.t()
  def encode(%Ucan{} = ucan) do
    "#{ucan.signed_data}.#{ucan.signature}"
  end

  @doc """
  Validate the UCAN token's signature and timestamps

  - encoded_token - Ucan token
  """
  @spec validate(String.t()) :: :ok | {:error, String.t() | map()}
  def validate(encoded_ucan) do
    with {:ok, {_header, payload}} <- parse_encoded_ucan(encoded_ucan),
         :ok <- is_expired?(payload),
         :ok <- is_too_early?(payload) do
      [encoded_header, encoded_payload, encoded_sign] = String.split(encoded_ucan, ".")
      {:ok, signature} = Base.url_decode64(encoded_sign, padding: false)
      data = "#{encoded_header}.#{encoded_payload}"
      verify_signature(payload.iss, data, signature)
    end
  end

  defp add_nonce(true), do: Utils.generate_nonce()
  defp add_nonce(false), do: nil

  @spec sign_with_payload(payload :: UcanPayload.t(), keypair :: struct()) :: Ucan.t()
  defp sign_with_payload(payload, keypair) do
    # TODO ExUcan.Core.Plugins.verify_issuer_alg
    header = %UcanHeader{alg: keypair.jwt_alg, typ: @token_type}
    encoded_header = encode_ucan_parts(header)
    encoded_payload = encode_ucan_parts(payload)

    signed_data = "#{encoded_header}.#{encoded_payload}"
    signature = Keymaterial.sign(keypair, signed_data)
    IO.inspect(signature)

    %Ucan{
      header: header,
      payload: payload,
      signed_data: signed_data,
      signature: Base.url_encode64(signature, padding: false)
    }
  end

  @spec encode_ucan_parts(UcanHeader.t() | UcanPayload.t()) :: String.t()
  defp encode_ucan_parts(data) do
    data
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  @spec is_expired?(UcanPayload.t()) :: :ok | {:error, String.t()}
  defp is_expired?(%UcanPayload{} = ucan_payload) do
    if ucan_payload.exp < DateTime.utc_now() |> DateTime.to_unix() do
      :ok
    else
      {:error, "Ucan token is already expired"}
    end
  end

  @spec is_too_early?(UcanPayload.t()) :: :ok | {:error, String.t()}
  defp is_too_early?(%UcanPayload{nbf: nbf}) do
    if nbf > DateTime.utc_now() |> DateTime.to_unix() do
      :ok
    else
      {:error, "Ucan token is not yet active"}
    end
  end

  @spec parse_encoded_ucan(String.t()) ::
          {:ok, {UcanHeader.t(), UcanPayload.t()}} | {:error, String.t() | map()}
  def parse_encoded_ucan(encoded_ucan) do
    opts = [padding: false]

    with {:ok, {header, payload, _sign}} <- tear_into_parts(encoded_ucan),
         {:ok, decoded_header} <- Base.url_decode64(header, opts),
         {:ok, header} <- Jason.decode(decoded_header, keys: :atoms),
         {:ok, decoded_payload} <- Base.url_decode64(payload, opts),
         {:ok, payload} <- Jason.decode(decoded_payload, keys: :atoms) do
      {:ok, {struct(UcanHeader, header), struct(UcanPayload, payload)}}
    end
  end

  @spec tear_into_parts(String.t()) ::
          {:ok, {String.t(), String.t(), String.t()}} | {:error, String.t()}
  defp tear_into_parts(encoded_ucan) do
    err_msg =
      "Can't parse UCAN: #{encoded_ucan}: Expected JWT format: 3 dot-separated base64url-encoded values."

    case String.split(encoded_ucan, ".") |> List.to_tuple() do
      {"", _, _} -> {:error, err_msg}
      {_, "", _} -> {:error, err_msg}
      {_, _, ""} -> {:error, err_msg}
      ucan_parts -> {:ok, ucan_parts}
    end
  end

  @spec verify_signature(String.t(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def verify_signature(did, data, signature) do
    with {:ok, public_key} <- Crypto.did_to_publickey(did),
         true <- :public_key.verify(data, :ignored, signature, {:ed_pub, :ed25519, public_key}) do
      :ok
    else
      false -> {:error, "Failed to verify signature, check the params and try again"}
      err -> err
    end
  end
end
