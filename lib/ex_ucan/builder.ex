defmodule ExUcan.Builder do
  @moduledoc """
  Builder functions for UCAN tokens
  """
  alias ExUcan.Core.Structs.UcanPayload
  alias ExUcan.Core.Token
  alias ExUcan.Keymaterial.Ed25519.Keypair
  alias ExUcan.Core.Capability

  @type t :: %__MODULE__{
          issuer: Keypair,
          audience: String.t(),
          capabilities: list(Capability),
          lifetime: number(),
          expiration: number(),
          not_before: number(),
          # Add Facts struct later
          facts: map(),
          proofs: list(String.t()),
          add_nonce?: boolean()
        }
  defstruct [
    :issuer,
    :audience,
    :capabilities,
    :lifetime,
    :expiration,
    :not_before,
    :facts,
    :proofs,
    :add_nonce?
  ]

  @doc """
    Create an empty builder.
    Before finalising the builder, we need to at least call:
    - `issued_by`
    - `to_audience` and one of
    - `with_lifetime` or `with_expiration`.
    To finalise the builder, call its `build` or `build_parts` method.
  """
  @spec default() :: __MODULE__.t()
  def default() do
    %__MODULE__{
      issuer: nil,
      audience: nil,
      capabilities: [],
      lifetime: nil,
      expiration: nil,
      not_before: nil,
      facts: %{},
      proofs: [],
      add_nonce?: false
    }
  end

  @doc """
  The UCAN must be signed with the private key of the issuer to be valid.
  """
  @spec issued_by(__MODULE__.t(), Keypair) :: __MODULE__.t()
  def issued_by(%__MODULE__{} = builder, keypair) do
    %{builder | issuer: keypair}
  end

  @doc """
  This is the identity this UCAN transfers rights to.

  It could e.g. be the DID of a service you're posting this UCAN as a JWT to,
  or it could be the DID of something that'll use this UCAN as a proof to
  continue the UCAN chain as an issuer.
  """
  @spec for_audience(__MODULE__.t(), String.t()) :: __MODULE__.t()
  def for_audience(builder, audience) do
    %{builder | audience: audience}
  end

  @doc """
  The number of seconds into the future (relative to when build() is
  invoked) to set the expiration. This is ignored if an explicit expiration
  is set.
  """
  @spec with_lifetime(__MODULE__.t(), integer()) :: __MODULE__.t()
  def with_lifetime(builder, seconds) do
    %{builder | lifetime: seconds}
  end

  @doc """
  Set the POSIX timestamp (in seconds) for when the UCAN should expire.
  Setting this value overrides a configured lifetime value.
  """
  @spec with_expiration(__MODULE__.t(), integer()) :: __MODULE__.t()
  def with_expiration(builder, timestamp) do
    %{builder | expiration: timestamp}
  end

  @doc """
  Set the POSIX timestamp (in seconds) of when the UCAN becomes active.
  """
  @spec not_before(__MODULE__.t(), integer()) :: __MODULE__.t()
  def not_before(builder, timestamp) do
    %{builder | not_before: timestamp}
  end

  @doc """
  Add a fact or proof of knowledge to this UCAN.
  """
  @spec with_fact(__MODULE__.t(), String.t(), any()) :: __MODULE__.t()
  def with_fact(builder, key, fact) do
    %{builder | facts: Map.put(builder.facts, key, fact)}
  end

  @doc """
  Will ensure that the built UCAN includes a number used once.
  """
  @spec with_nonce(__MODULE__.t()) :: __MODULE__.t()
  def with_nonce(builder) do
    %{builder | add_nonce?: true}
  end

  # TODO: try to do this function
  @doc """
  Includes a UCAN in the list of proofs for the UCAN to be built.
  Note that the proof's audience must match this UCAN's issuer
  or else the proof chain will be invalidated!
  The proof is encoded into a [Cid], hashed via the [UcanBuilder::default_hasher()]
  algorithm, unless one is provided.
  """
  @spec witnessed_by(__MODULE__.t()) :: __MODULE__.t()
  def witnessed_by(builder) do
    builder
  end

  @doc """
  Claim a capability by inheritance (from an authorizing proof) or
  implicitly by ownership of the resource by this UCAN's issuer
  """
  @spec claiming_capability(__MODULE__.t(), Capability) :: __MODULE__.t()
  def claiming_capability(builder, capability) do
    %{builder | capabilities: builder.capabilities ++ [capability]}
  end

  def delegating_from(builder) do
    builder
  end

  # TODO: docs
  @doc """

  """
  @spec build!(__MODULE__.t()) :: String.t()
  def build!(builder) do
    case Token.build_payload(builder) do
      {:ok, payload} -> payload
      {:error, err} -> raise err
    end
  end

  @spec build(__MODULE__.t()) :: {:ok, UcanPayload.t()} | {:error, String.t()}
  def build(builder) do
    Token.build_payload(builder)
  end
end
