module TestConstants

open NBitcoin
open DotNetLightning.Utils
open DotNetLightning.Chain
open DotNetLightning.Infrastructure
open System.Net
open Foq

type TestEntity =
    {
        Seed: uint256
        KeyRepo: IKeysRepository
        NodeParams: NodeParams
    }

let fundingSatoshis = 1000000L |> Money.Satoshis
let pushMsat = 200000000L |> LNMoney.MilliSatoshis
let feeratePerKw = 10000u |> FeeRatePerKw 
let hex = NBitcoin.DataEncoders.HexEncoder()
let aliceNodeSecret = 
    Key(hex.DecodeData("1111111111111111111111111111111111111111111111111111111111111111"))
        
let aliceChannelKeysSeed = 
    hex.DecodeData("2222222222222222222222222222222222222222222222222222222222222222")
    |> uint256
      
let bobNodeSecret =
    Key(hex.DecodeData("0202020202020202020202020202020202020202020202020202020202020202"))
    // Key(hex.DecodeData("3333333333333333333333333333333333333333333333333333333333333333"))
    
let bobChannelKeysSeed =
    hex.DecodeData("4444444444444444444444444444444444444444444444444444444444444444")
    |> uint256
    
let getAliceParam() =
    let p = NodeParams()
    p.Alias <- "alice"
    p.Color <- { RGB.Red = 1uy; Green = 2uy; Blue = 3uy }
    p.PublicAddresses <- [IPEndPoint.Parse("127.0.0.1:9731")]
    p.MaxHTLCValueInFlightMSat <- LNMoney.MilliSatoshis(150000000UL)
    p.MaxAcceptedHTLCs <- 100us
    // p.ExpirtyDeltaBlocks <- 144
    p.HTLCMinimumMSat <- LNMoney.Zero
    p.MinDepthBlocks <- 3u |> BlockHeight
    // p.SmartFeeNBlocks <- 3
    p.ToRemoteDelayBlocks <- BlockHeightOffset 720us
    p.MaxToLocalDelayBlocks <- BlockHeightOffset 1000us
    p.FeeBaseMSat <- 546000UL |> LNMoney.MilliSatoshis
    p.FeeProportionalMillionths <- 10u
    p.ReserveToFundingRatio <- 0.01
    p.DBType <- SupportedDBType.Null
    let keyRepo =
        DefaultKeyRepository(aliceChannelKeysSeed)
    {
        TestEntity.Seed = [| for _ in 0..31 -> 0uy |] |> uint256
        KeyRepo = keyRepo
        NodeParams = p
    }
    
let getBobParam() =
    let p = NodeParams()
    let keyRepo = DefaultKeyRepository(bobChannelKeysSeed)
    {
        TestEntity.Seed = [| for _ in 0..31 -> 1uy |] |> uint256
        KeyRepo = keyRepo
        NodeParams = p
    }
