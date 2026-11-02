"""Unit tests for the snarkjs conversion.

The end-to-end check needs cargo, node and ~10 s; these do not. They pin the one
thing that would silently corrupt a cross-verification: the shape and ordering of
the coordinates handed to the other implementation.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from tools.crossverify import run  # noqa: E402

RAW = {
    "n_public": 2,
    "alpha": ["0x01", "0x02"],
    "beta": [["0x03", "0x04"], ["0x05", "0x06"]],
    "gamma": [["0x07", "0x08"], ["0x09", "0x0a"]],
    "delta": [["0x0b", "0x0c"], ["0x0d", "0x0e"]],
    "ic": [["0x10", "0x11"], ["0x12", "0x13"], ["0x14", "0x15"]],
    "pi_a": ["0x16", "0x17"],
    "pi_b": [["0x18", "0x19"], ["0x1a", "0x1b"]],
    "pi_c": ["0x1c", "0x1d"],
    "public_inputs": ["0x1e", "0x1f"],
}


class Conversion(unittest.TestCase):
    def setUp(self) -> None:
        self.vk, self.proof, self.public = run.to_snarkjs(RAW)

    def test_hex_becomes_decimal(self) -> None:
        self.assertEqual(self.vk["vk_alpha_1"], ["1", "2", "1"])
        self.assertEqual(self.public, ["30", "31"])

    def test_g1_carries_the_projective_one(self) -> None:
        self.assertEqual(len(self.vk["IC"][0]), 3)
        self.assertEqual(self.vk["IC"][0][2], "1")
        self.assertEqual(self.proof["pi_a"][2], "1")

    def test_g2_is_two_fq2_pairs_plus_one(self) -> None:
        beta = self.vk["vk_beta_2"]
        self.assertEqual(len(beta), 3)
        self.assertEqual(beta[0], ["3", "4"])
        self.assertEqual(beta[1], ["5", "6"])
        self.assertEqual(beta[2], ["1", "0"])

    def test_npublic_matches_ic_length(self) -> None:
        self.assertEqual(self.vk["nPublic"], 2)
        self.assertEqual(len(self.vk["IC"]), self.vk["nPublic"] + 1)

    def test_curve_and_protocol_are_named(self) -> None:
        for doc in (self.vk, self.proof):
            self.assertEqual(doc["protocol"], "groth16")
            self.assertEqual(doc["curve"], "bn128")

    def test_public_input_order_is_preserved(self) -> None:
        self.assertEqual(self.public, ["30", "31"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
