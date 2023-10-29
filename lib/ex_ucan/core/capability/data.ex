defmodule ExUcan.Core.Capability do
  # TODO: All the docs needed
  @type t :: %__MODULE__{
          resource: String.t(),
          ability: String.t(),
          caveat: list(map())
        }
  defstruct [:resource, :ability, :caveat]

  @spec new(String.t(), String.t(), list()) :: __MODULE__.t()
  def new(resource, ability, caveat) do
    %__MODULE__{
      resource: resource,
      ability: ability,
      caveat: caveat
    }
  end
end

defmodule ExUcan.Core.Capabilities do
  @moduledoc """
  Capabilities always deals with capabilites as map of maps
  map<String: map<String: list()>>
  """
  alias ExUcan.Core.Capability
  # TODO: All the docs needed

  # def validate(capabilities) when is_map(capabilities) do
  #   capabilities
  #   |> Enum.reduce_while(%{}, fn {resource, ability}, caps ->
  #     # ability should be map
  #     #   iter through ability

  #   end)
  # end

  def validate(_), do: {:error, "Capabilities must be an object."}

  @spec map_to_sequence(map()) :: list(Capability.t())
  def map_to_sequence(capabilities) do
    capabilities
    |> Enum.reduce([], fn {resource, ability}, caps ->
      [{ability, caveat}] = Map.to_list(ability)
      caps ++ [Capability.new(resource, ability, caveat)]
    end)
  end

  @spec sequence_to_map(list(Capability.t())) :: map()
  def sequence_to_map(capabilites) do
    capabilites
    |> Enum.reduce(%{}, fn %Capability{} = cap, caps ->
      Map.put(caps, cap.resource, %{cap.ability => cap.caveat})
    end)
  end
end
