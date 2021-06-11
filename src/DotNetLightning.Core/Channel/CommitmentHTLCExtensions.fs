namespace DotNetLightning.Channel

open System
open NBitcoin
open NBitcoin.BuilderExtensions
open DotNetLightning.Utils
open DotNetLightning.Crypto

open ResultUtils
open ResultUtils.Portability

type CommitmentHTLCParameters = {
    LocalHTLCPubKey: HtlcPubKey
    RemoteHTLCPubKey: HtlcPubKey
    RevocationPubKey: RevocationPubKey
    PaymentHash: byte[]
}
    with
    static member TryExtractParameters (scriptPubKey: Script): Option<CommitmentHTLCParameters> =
        let ops =
            scriptPubKey.ToOps()
            // we have to collect it into a list and convert back to a seq
            // because the IEnumerable that NBitcoin gives us is internally
            // mutable.
            |> List.ofSeq
            |> Seq.ofList
        let checkOpCode(opcodeType: OpcodeType) = seqParser<Op> {
            let! op = SeqParser.next()
            if op.Code = opcodeType then
                return ()
            else
                return! SeqParser.abort()
        }
        let parseToCompletionResult =
            SeqParser.parseToCompletion ops <| seqParser {
                do! checkOpCode OpcodeType.OP_DUP
                do! checkOpCode OpcodeType.OP_HASH160
                let! opRevocationPubKey = SeqParser.next()
                let! revocationPubKey = seqParser {
                    match opRevocationPubKey.PushData with
                    | null -> return! SeqParser.abort()
                    | bytes ->
                        try
                            return RevocationPubKey.FromBytes bytes
                        with
                        | :? FormatException -> return! SeqParser.abort()
                }
                do! checkOpCode OpcodeType.OP_EQUAL
                do! checkOpCode OpcodeType.OP_IF
                do! checkOpCode OpcodeType.OP_CHECKSIG
                do! checkOpCode OpcodeType.OP_ELSE
                let! opRemoteHTLCPubKey = SeqParser.next()
                let! remoteHTLCPubKey = seqParser {
                    match opRemoteHTLCPubKey.PushData with
                    | null -> return! SeqParser.abort()
                    | bytes ->
                        try
                            return PubKey bytes
                        with
                        | :? FormatException -> return! SeqParser.abort()
                }
                do! checkOpCode OpcodeType.OP_SWAP
                do! checkOpCode OpcodeType.OP_SIZE
                //
                do! checkOpCode OpcodeType.OP_EQUAL
                do! checkOpCode OpcodeType.OP_NOTIF
                do! checkOpCode OpcodeType.OP_DROP
                do! checkOpCode OpcodeType.OP_2
                do! checkOpCode OpcodeType.OP_SWAP
                let! opLocalHtlcPubKey = SeqParser.next()
                let! localHtlcPubKey = seqParser {
                    match opLocalHtlcPubKey.PushData with
                    | null -> return! SeqParser.abort()
                    | bytes ->
                        try
                            return PubKey bytes
                        with
                        | :? FormatException -> return! SeqParser.abort()
                }
                do! checkOpCode OpcodeType.OP_2
                do! checkOpCode OpcodeType.OP_CHECKMULTISIG
                do! checkOpCode OpcodeType.OP_ELSE
                do! checkOpCode OpcodeType.OP_HASH160
                let! opPaymentHash = SeqParser.next()
                let! paymentHash = seqParser {
                    match opPaymentHash.PushData with
                    | null -> return! SeqParser.abort()
                    | bytes ->
                        try
                            return bytes
                        with
                        | :? FormatException -> return! SeqParser.abort()
                }
                do! checkOpCode OpcodeType.OP_EQUALVERIFY
                do! checkOpCode OpcodeType.OP_CHECKSIG
                do! checkOpCode OpcodeType.OP_ENDIF
                do! checkOpCode OpcodeType.OP_ENDIF
                
                return {
                    RevocationPubKey = revocationPubKey
                    RemoteHTLCPubKey = HtlcPubKey.HtlcPubKey remoteHTLCPubKey
                    LocalHTLCPubKey = HtlcPubKey.HtlcPubKey localHtlcPubKey
                    PaymentHash = paymentHash
                }
            }
        match parseToCompletionResult with
        | Ok data -> Some data
        | Error _consumeAllError -> None

type internal CommitmentToLocalExtension() =
    inherit BuilderExtension()
        override self.CanGenerateScriptSig (scriptPubKey: Script): bool =
            (CommitmentHTLCParameters.TryExtractParameters scriptPubKey).IsSome

        override self.GenerateScriptSig(scriptPubKey: Script, keyRepo: IKeyRepository, signer: ISigner): Script =
            let parameters =
                match (CommitmentHTLCParameters.TryExtractParameters scriptPubKey) with
                | Some parameters -> parameters
                | None ->
                    failwith
                        "NBitcoin should not call this unless CanGenerateScriptSig returns true"
            let pubKey = keyRepo.FindKey scriptPubKey
            // FindKey will return null if it can't find a key for
            // scriptPubKey. If we can't find a valid key then this method
            // should return null, indicating to NBitcoin that the sigScript
            // could not be generated.
            match pubKey with
            | null -> null
            | _ when pubKey = parameters.RevocationPubKey.RawPubKey() ->
                let revocationSig = signer.Sign (parameters.RevocationPubKey.RawPubKey())
                Script [
                    Op.GetPushOp (revocationSig.ToBytes())
                    Op.op_Implicit OpcodeType.OP_TRUE
                ]
            | _ when pubKey = parameters.LocalDelayedPubKey.RawPubKey() ->
                let localDelayedSig = signer.Sign (parameters.LocalDelayedPubKey.RawPubKey())
                Script [
                    Op.GetPushOp (localDelayedSig.ToBytes())
                    Op.op_Implicit OpcodeType.OP_FALSE
                ]
            | _ -> null

        override self.CanDeduceScriptPubKey(_scriptSig: Script): bool =
            false

        override self.DeduceScriptPubKey(_scriptSig: Script): Script =
            raise <| NotSupportedException()

        override self.CanEstimateScriptSigSize(_scriptPubKey: Script): bool =
            false

        override self.EstimateScriptSigSize(_scriptPubKey: Script): int =
            raise <| NotSupportedException()

        override self.CanCombineScriptSig(_scriptPubKey: Script, _a: Script, _b: Script): bool = 
            false

        override self.CombineScriptSig(_scriptPubKey: Script, _a: Script, _b: Script): Script =
            raise <| NotSupportedException()

        override self.IsCompatibleKey(pubKey: PubKey, scriptPubKey: Script): bool =
            match CommitmentHTLCParameters.TryExtractParameters scriptPubKey with
            | None -> false
            | Some parameters ->
                parameters.RevocationPubKey.RawPubKey() = pubKey
                || parameters.LocalDelayedPubKey.RawPubKey() = pubKey


