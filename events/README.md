# @backplane-labs/kratos-events

TypeScript (protobuf-es v2) of backplane-kratos's event payloads,
`proto/kratos/events/v1`: `FlowEvent`, `IdentityEvent`, `SessionsRevoked`.
Released with backplane-kratos, same version.

```ts
import { FlowEventSchema } from "@backplane-labs/kratos-events/kratos/events/v1/events_pb.js";
```

A product whose own protos import `kratos/events/v1/events.proto` points
protoc-gen-es at this package:
`rewrite_imports=./kratos/**/*_pb.js:@backplane-labs/kratos-events`.
