defmodule ExUcan.Core.Utils do
  @moduledoc """
  Core utils
  """
  @chars "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

  # TODO: docs
  def generate_nonce(len \\ 6)

  def generate_nonce(len) do
    Enum.reduce(1..len, "", fn _, nonce ->
      nonce <> String.at(@chars, :rand.uniform(String.length(@chars) - 1))
    end)
  end
end
