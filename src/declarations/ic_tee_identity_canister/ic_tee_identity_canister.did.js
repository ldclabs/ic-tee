export const idlFactory = ({ IDL }) => {
  const UpgradeArgs = IDL.Record({
    'session_expires_in_ms' : IDL.Opt(IDL.Nat64),
    'name' : IDL.Opt(IDL.Text),
  });
  const InitArgs = IDL.Record({
    'session_expires_in_ms' : IDL.Nat64,
    'name' : IDL.Text,
  });
  const CanArgs = IDL.Variant({ 'Upgrade' : UpgradeArgs, 'Init' : InitArgs });
  const Delegation = IDL.Record({
    'pubkey' : IDL.Vec(IDL.Nat8),
    'targets' : IDL.Opt(IDL.Vec(IDL.Principal)),
    'expiration' : IDL.Nat64,
  });
  const SignedDelegation = IDL.Record({
    'signature' : IDL.Vec(IDL.Nat8),
    'delegation' : Delegation,
  });
  const Result = IDL.Variant({ 'Ok' : SignedDelegation, 'Err' : IDL.Text });
  const State = IDL.Record({
    'session_expires_in_ms' : IDL.Nat64,
    'name' : IDL.Text,
    'sign_in_count' : IDL.Nat64,
  });
  const Result_1 = IDL.Variant({ 'Ok' : State, 'Err' : IDL.Text });
  const SignInResponse = IDL.Record({
    'user_key' : IDL.Vec(IDL.Nat8),
    'seed' : IDL.Vec(IDL.Nat8),
    'expiration' : IDL.Nat64,
  });
  const Result_2 = IDL.Variant({ 'Ok' : SignInResponse, 'Err' : IDL.Text });
  return IDL.Service({
    'get_delegation' : IDL.Func(
        [IDL.Vec(IDL.Nat8), IDL.Vec(IDL.Nat8), IDL.Nat64],
        [Result],
        ['query'],
      ),
    'get_state' : IDL.Func([], [Result_1], ['query']),
    'sign_in' : IDL.Func([IDL.Text, IDL.Vec(IDL.Nat8)], [Result_2], []),
    'whoami' : IDL.Func([], [IDL.Principal], ['query']),
  });
};
export const init = ({ IDL }) => {
  const UpgradeArgs = IDL.Record({
    'session_expires_in_ms' : IDL.Opt(IDL.Nat64),
    'name' : IDL.Opt(IDL.Text),
  });
  const InitArgs = IDL.Record({
    'session_expires_in_ms' : IDL.Nat64,
    'name' : IDL.Text,
  });
  const CanArgs = IDL.Variant({ 'Upgrade' : UpgradeArgs, 'Init' : InitArgs });
  return [IDL.Opt(CanArgs)];
};
