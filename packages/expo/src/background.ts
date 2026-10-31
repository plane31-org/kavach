/**
 * Background location glue (profile section 3): the task calls `enqueueLocation` for each new
 * sample, then `sync`. Delivery is the SDK's; scheduling is the host's.
 */
import { locationFromDegrees, type Client, type LocationStatus } from "@kavach/core";

/** The shape `expo-location` hands a background task. */
export interface ExpoLocationObject {
  coords: { latitude: number; longitude: number; accuracy: number | null };
  timestamp: number;
}

export interface BackgroundResult {
  enqueued: number;
  skipped: number;
  synced: boolean;
  error: string | undefined;
}

/**
 * Handle one batch from the location task. Samples older than `lastHandled` are skipped, and
 * each sample is enqueued under an idempotency key from its timestamp, so a redelivered batch
 * duplicates no record even in a fresh process whose `lastHandled` starts at zero; unusable
 * samples are sent as status 2.
 */
export async function handleBackgroundLocations(client: Client, locations: readonly ExpoLocationObject[], lastHandled: { timestamp: number }): Promise<BackgroundResult> {
  const result: BackgroundResult = { enqueued: 0, skipped: 0, synced: false, error: undefined };
  const sorted = [...locations].sort((a, b) => a.timestamp - b.timestamp);
  for (const l of sorted) {
    if (l.timestamp <= lastHandled.timestamp) {
      result.skipped++;
      continue;
    }
    const usable = Number.isFinite(l.coords.latitude) && Number.isFinite(l.coords.longitude) && l.coords.accuracy !== null && l.coords.accuracy >= 0;
    const status: LocationStatus = usable ? 0 : 2;
    const location = usable
      ? locationFromDegrees(l.coords.latitude, l.coords.longitude, l.coords.accuracy ?? 0, BigInt(Math.round(l.timestamp)), status)
      : locationFromDegrees(0, 0, 0, BigInt(Math.round(l.timestamp)), 2);
    try {
      await client.enqueueLocation(location, { idempotencyKey: `bg:${Math.round(l.timestamp)}` });
      result.enqueued++;
      lastHandled.timestamp = l.timestamp;
    } catch (e) {
      result.error = e instanceof Error ? e.message : String(e);
      break;
    }
  }
  try {
    await client.sync();
    result.synced = true;
  } catch (e) {
    result.error ??= e instanceof Error ? e.message : String(e);
  }
  return result;
}

/** The subset of `expo-task-manager` used to register the task. */
export interface TaskManagerLike {
  defineTask(name: string, executor: (body: { data: unknown; error: { message: string } | null }) => void | Promise<void>): void;
}

/**
 * Register the background location task. `getClient` opens or returns the client; the executor
 * never holds a client across runs, since the OS may start a fresh process for each.
 */
export function defineLocationTask(taskManager: TaskManagerLike, name: string, getClient: () => Promise<Client>, lastHandled: { timestamp: number } = { timestamp: 0 }): void {
  taskManager.defineTask(name, async ({ data, error }) => {
    if (error) return;
    const locations = (data as { locations?: ExpoLocationObject[] } | undefined)?.locations ?? [];
    if (locations.length === 0) return;
    const client = await getClient();
    await handleBackgroundLocations(client, locations, lastHandled);
  });
}
