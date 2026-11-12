// Two failure kinds, and conflating them is the most damaging bug this code could have.
//
// Refusal: the file, the message or the parameters are wrong — tampering, a protocol deviation, a
// format this reader does not implement. NotRegistered: a well-formed, correctly signed response
// from a key that is not in the list.
//
// A user told "not registered" when the file was tampered with keeps retrying a device that was
// never the problem; an operator who sees "refused" for an unprovisioned device hunts for a fault
// that does not exist. Parsing lives in cbor.js and still has to report a refusal, so the classes
// sit here rather than in either consumer.

export class Refusal extends Error {}

export class NotRegistered extends Error {
  constructor(message, uid) {
    super(message);
    this.uid = uid;
  }
}
