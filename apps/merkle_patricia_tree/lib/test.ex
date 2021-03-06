defmodule MerklePatriciaTree.Test do
  @moduledoc """
  Helper functions related to creating a MerklePatriciaTree
  database in :ets or :rocksdb. This is to be used when
  you need to have a persisted table for a test case, which
  is basically any test that involves these tables. The tables
  generated by this module are supposed to be exceedingly temporary.
  """

  @doc """
  Returns a random :ets database suitable for testing

  ## Examples

      iex> {MerklePatriciaTree.DB.ETS, db_ref} = MerklePatriciaTree.Test.random_ets_db()
      iex> :ets.info(db_ref)[:type]
      :set

      iex> {MerklePatriciaTree.DB.ETS, db_ref} = MerklePatriciaTree.Test.random_ets_db(:test1)
      iex> :ets.info(db_ref)[:name]
      :test1
  """
  def random_ets_db(name \\ nil) do
    MerklePatriciaTree.DB.ETS.init(name || MerklePatriciaTree.Test.random_atom(20))
  end

  @doc """
  Returns a semi-random string of length `length` that
  can be represented by alphanumeric characters.

  Adopted from https://stackoverflow.com/a/32002566.

  ## Examples

      iex> MerklePatriciaTree.Test.random_string(20) |> is_binary
      true

      iex> String.length(MerklePatriciaTree.Test.random_string(20))
      20

      iex> MerklePatriciaTree.Test.random_string(20) == MerklePatriciaTree.Test.random_string(20)
      false
  """
  def random_string(length) do
    length
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64()
    |> binary_part(0, length)
  end

  @doc """
  Returns a semi-random atom, similar to `random_string/1`, but
  is an atom. This is obviously not to be used in production since
  atoms are not garbage collected.

  ## Examples

      iex> MerklePatriciaTree.Test.random_atom(20) |> is_atom
      true

      iex> MerklePatriciaTree.Test.random_atom(20) |> Atom.to_string |> String.length
      20

      iex> MerklePatriciaTree.Test.random_atom(20) == MerklePatriciaTree.Test.random_atom(20)
      false
  """
  def random_atom(length) do
    length |> random_string |> String.to_atom()
  end
end
