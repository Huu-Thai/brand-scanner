import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiSecurity,
  ApiServiceUnavailableResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Principal } from '../../common/decorators/principal.decorator.js';
import { ExpensiveThrottle } from '../../common/guards/api-key-throttler.guard.js';
import type { ApiPrincipal } from '../../common/guards/api-key.guard.js';
import { AlertChannelsService } from './alert-channels.service.js';
import { AlertSubscriptionsService } from './alert-subscriptions.service.js';
import { AlertsService } from './alerts.service.js';
import {
  AlertChannelDto,
  AlertChannelWithSecretDto,
  AlertDeliveryPageDto,
  AlertSubscriptionDto,
  ChannelTestResultDto,
  CreateAlertChannelDto,
  CreateAlertSubscriptionDto,
  ListAlertDeliveriesQueryDto,
  UpdateAlertChannelDto,
  UpdateAlertSubscriptionDto,
} from './dto/alert.dto.js';

@ApiTags('alerts')
@ApiSecurity('api-key')
@ApiServiceUnavailableResponse({
  description: 'ALERT_ENCRYPTION_KEY is not configured',
})
@Controller()
export class AlertsController {
  constructor(
    private readonly channels: AlertChannelsService,
    private readonly subscriptions: AlertSubscriptionsService,
    private readonly alerts: AlertsService,
  ) {}

  @Get('alert-channels')
  @ApiOperation({ summary: 'Alert channels (targets are masked)' })
  @ApiOkResponse({ type: [AlertChannelDto] })
  listChannels() {
    return this.channels.list();
  }

  @Post('alert-channels')
  @ApiOperation({
    summary: 'Create a webhook, Slack or e-mail channel',
    description:
      'Webhook channels get a signing secret, returned only in this response.',
  })
  @ApiCreatedResponse({ type: AlertChannelWithSecretDto })
  createChannel(
    @Body() dto: CreateAlertChannelDto,
    @Principal() p: ApiPrincipal,
  ) {
    return this.channels.create(dto, p.actor);
  }

  @Get('alert-channels/:id')
  @ApiOkResponse({ type: AlertChannelDto })
  getChannel(@Param('id', ParseUUIDPipe) id: string) {
    return this.channels.findOne(id);
  }

  @Patch('alert-channels/:id')
  @ApiOkResponse({ type: AlertChannelDto })
  updateChannel(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateAlertChannelDto,
    @Principal() p: ApiPrincipal,
  ) {
    return this.channels.update(id, dto, p.actor);
  }

  @Delete('alert-channels/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiNoContentResponse({
    description: 'Its subscriptions and delivery history are removed too',
  })
  removeChannel(
    @Param('id', ParseUUIDPipe) id: string,
    @Principal() p: ApiPrincipal,
  ) {
    return this.channels.remove(id, p.actor);
  }

  @Post('alert-channels/:id/rotate-secret')
  @ApiOperation({
    summary:
      'New webhook signing secret (returned once; the old one stops working)',
  })
  @ApiCreatedResponse({ type: AlertChannelWithSecretDto })
  rotate(@Param('id', ParseUUIDPipe) id: string, @Principal() p: ApiPrincipal) {
    return this.channels.rotateSecret(id, p.actor);
  }

  @Post('alert-channels/:id/test')
  @HttpCode(HttpStatus.OK)
  @ExpensiveThrottle()
  @ApiOperation({
    summary:
      'Send a sample alert now and report whether the channel accepted it',
  })
  @ApiOkResponse({ type: ChannelTestResultDto })
  test(@Param('id', ParseUUIDPipe) id: string) {
    return this.alerts.test(id);
  }

  @Get('alert-subscriptions')
  @ApiQuery({ name: 'channelId', required: false })
  @ApiOkResponse({ type: [AlertSubscriptionDto] })
  listSubscriptions(
    @Query('channelId', new ParseUUIDPipe({ optional: true }))
    channelId?: string,
  ) {
    return this.subscriptions.list(channelId);
  }

  @Post('alert-subscriptions')
  @ApiOperation({
    summary:
      'Route events (optionally of one brand, above a risk score) to a channel',
  })
  @ApiCreatedResponse({ type: AlertSubscriptionDto })
  createSubscription(
    @Body() dto: CreateAlertSubscriptionDto,
    @Principal() p: ApiPrincipal,
  ) {
    return this.subscriptions.create(dto, p.actor);
  }

  @Patch('alert-subscriptions/:id')
  @ApiOkResponse({ type: AlertSubscriptionDto })
  updateSubscription(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateAlertSubscriptionDto,
    @Principal() p: ApiPrincipal,
  ) {
    return this.subscriptions.update(id, dto, p.actor);
  }

  @Delete('alert-subscriptions/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  removeSubscription(
    @Param('id', ParseUUIDPipe) id: string,
    @Principal() p: ApiPrincipal,
  ) {
    return this.subscriptions.remove(id, p.actor);
  }

  @Get('alert-deliveries')
  @ApiOperation({ summary: 'Delivery log (newest first by default)' })
  @ApiOkResponse({ type: AlertDeliveryPageDto })
  listDeliveries(@Query() q: ListAlertDeliveriesQueryDto) {
    return this.alerts.deliveries(q);
  }
}
