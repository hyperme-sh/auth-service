import type {Transport, Request, Offer, Scope} from 'sea-device-link';
export type RelayAction = 'admit'|'create'|'join'|'offer'|'send'|'receive'|'complete'|'completed'|'cancel';
export type RelayCall = {session:string;action:RelayAction;scope:Scope;payload:unknown;headers:Record<string,string>};
/** Trusted HTTP adapter: configured HTTPS endpoint, bounded JSON, no redirects,
 * no request logging; add the source's local bearer only for sender calls. */
export type RelayRequester = (call:RelayCall)=>Promise<{status:number;body:{v:1;result:unknown}}>;
export type RelayOptions = {scope:Scope;session:string;role:'receiver'|'sender';capability:string;request:RelayRequester};
export type Relay = Transport & {
 admit(request:Request,receiverCapabilityHash:string,joinCapability:string):Promise<void>;
 create(request:Request,joinCapability:string):Promise<void>;
 join(offer:Offer,joinCapability:string):Promise<void>;
 offer():Promise<Offer|null>;
 cancel():Promise<void>;
 close():void;
};
/** Independently generate receiver, join, and sender capabilities. Never reuse. */
export function capabilityHash(capability:string):Promise<string>;
export function newCapability():string;
export function createRelay(options:RelayOptions):Relay;
