import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type CanArgs = { 'Upgrade' : UpgradeArgs } |
  { 'Init' : InitArgs };
/**
 * A delegation from one key to another.
 * 
 * If key A signs a delegation containing key B, then key B may be used to
 * authenticate as key A's corresponding principal(s).
 */
export interface Delegation {
  /**
   * The kinds of requests this delegation permits.
   */
  'permissions' : [] | [DelegationPermissions],
  /**
   * The delegated-to key.
   */
  'pubkey' : Uint8Array | number[],
  /**
   * If present, this delegation only applies to requests sent to one of these canisters.
   */
  'targets' : [] | [Array<Principal>],
  /**
   * A nanosecond timestamp after which this delegation is no longer valid.
   */
  'expiration' : bigint,
}
/**
 * The kinds of requests a [`Delegation`] permits.
 */
export type DelegationPermissions = {
    /**
     * All request types are permitted.
     */
    'all' : null
  } |
  {
    /**
     * Only query calls and `read_state` requests are permitted.
     */
    'queries' : null
  };
export interface InitArgs { 'session_expires_in_ms' : bigint, 'name' : string }
export type Result = { 'Ok' : SignedDelegation } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : State } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : SignInResponse } |
  { 'Err' : string };
export interface SignInResponse {
  /**
   * The user canister public key. This key is used to derive the user principal.
   */
  'user_key' : Uint8Array | number[],
  /**
   * The seed component used to derive the user key.
   */
  'seed' : Uint8Array | number[],
  /**
   * The session expiration time in nanoseconds since the UNIX epoch. This is the time at which
   * the delegation will no longer be valid.
   */
  'expiration' : bigint,
}
/**
 * SignedDelegation is a [`Delegation`] that has been signed by an [`Identity`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html).
 */
export interface SignedDelegation {
  /**
   * The signature for the delegation.
   */
  'signature' : Uint8Array | number[],
  /**
   * The signed delegation.
   */
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
