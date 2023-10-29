defmodule ExUcanTest do
  alias ExUcan.Builder
  alias ExUcan.Keymaterial.Ed25519.Keypair
  use ExUnit.Case
  doctest ExUcan

  setup do
    keypair = ExUcan.create_default_keypair()
    %{keypair: keypair}
  end

  test "create_default_keypair" do
    assert %Keypair{jwt_alg: "EdDSA"} = keypair = Keypair.create()
    assert is_binary(keypair.public_key)
    assert is_binary(keypair.secret_key)
  end

  @tag :exucan
  test "validate_token, success", meta do
    token =
      Builder.default()
      |> Builder.issued_by(meta.keypair)
      |> Builder.for_audience("did:key:z6MkwDK3M4PxU1FqcSt4quXghquH1MoWXGzTrNkNWTSy2NLD")
      |> Builder.with_expiration((DateTime.utc_now() |> DateTime.to_unix()) + 86_400)
      |> Builder.build!()
      |> ExUcan.sign(meta.keypair)
      |> ExUcan.encode()

      assert :ok = ExUcan.validate_token(token)
  end

  @tag :exucan
  test "invalid token, due to expiry", meta do
    token =
      Builder.default()
      |> Builder.issued_by(meta.keypair)
      |> Builder.for_audience("did:key:z6MkwDK3M4PxU1FqcSt4quXghquH1MoWXGzTrNkNWTSy2NLD")
      |> Builder.with_expiration((DateTime.utc_now() |> DateTime.to_unix()) - 5)
      |> Builder.build!()
      |> ExUcan.sign(meta.keypair)
      |> ExUcan.encode()

      assert {:error, "Ucan token is already expired"} = ExUcan.validate_token(token)
  end

  @tag :exucan
  test "invalid token, too early", meta do
    token =
      Builder.default()
      |> Builder.issued_by(meta.keypair)
      |> Builder.for_audience("did:key:z6MkwDK3M4PxU1FqcSt4quXghquH1MoWXGzTrNkNWTSy2NLD")
      |> Builder.with_expiration((DateTime.utc_now() |> DateTime.to_unix()) + 86_400)
      |> Builder.not_before((DateTime.utc_now() |> DateTime.to_unix()) + (div(86400, 2)))
      |> Builder.build!()
      |> ExUcan.sign(meta.keypair)
      |> ExUcan.encode()

      assert {:error, "Ucan token is not yet active"} = ExUcan.validate_token(token)
  end
end
