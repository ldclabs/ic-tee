import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type CanArgs = { 'Upgrade' : UpgradeArgs } |
  { 'Init' : InitArgs };
export interface Delegation {
  'pubkey' : Uint8Array | number[],
  'targets' : [] | [Array<Principal>],
  'expiration' : bigint,
}
export interface InitArgs { 'session_expires_in_ms' : bigint, 'name' : string }
export type Result = { 'Ok' : SignedDelegation } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : State } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : SignInResponse } |
  { 'Err' : string };
export interface SignInResponse {
  'user_key' : Uint8Array | number[],
  'seed' : Uint8Array | number[],
  'expiration' : bigint,
}
export interface SignedDelegation {
  'signature' : Uint8Array | number[],
  'delegation' : Delegation,
}
export interface State {
  'session_expires_in_ms' : bigint,
  'name' : string,
  'sign_in_count' : bigint,
}
export interface UpgradeArgs {
  'session_expires_in_ms' : [] | [bigint],
  'name' : [] | [string],
}
export interface _SERVICE {
  'get_delegation' : ActorMethod<
    [Uint8Array | number[], Uint8Array | number[], bigint],
    Result
  >,
  'get_state' : ActorMethod<[], Result_1>,
  'sign_in' : ActorMethod<[string, Uint8Array | number[]], Result_2>,
  'whoami' : ActorMethod<[], Principal>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
