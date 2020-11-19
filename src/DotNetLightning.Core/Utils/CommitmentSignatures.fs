module DotNetLightning.Utils

open System
open System.Net

open NBitcoin
open DotNetLightning.Utils
open DotNetLightning.Channel

type CommitmentSignatures private (signatures: Map<CommitmentNumber, TransactionSignature>) =
    new() = CommitmentSignatures(Map.empty)

    member this.AddCommitmentSignature(newCommitments: Commitments) = 
        failwith "not implemented yet!"