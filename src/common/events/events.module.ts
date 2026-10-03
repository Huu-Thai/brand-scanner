import { Global, Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { OutboxDispatcher } from './outbox/outbox.dispatcher.js';
import { OutboxRelay } from './outbox/outbox.relay.js';
import { TransactionalEventBus } from './transactional-event-bus.js';

@Global()
@Module({
  imports: [
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: '.',
      // A throwing listener propagates to the emitter, which is how before-events veto writes.
      ignoreErrors: false,
      verboseMemoryLeak: true,
    }),
  ],
  providers: [TransactionalEventBus, OutboxDispatcher, OutboxRelay],
  exports: [TransactionalEventBus, OutboxDispatcher],
})
export class EventsModule {}
