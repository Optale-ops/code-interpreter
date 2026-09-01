export interface PausableSource {
    pause(): unknown;
    resume(): unknown;
}

export interface BackpressureDestination {
    destroyed?: boolean;
    write(chunk: unknown): boolean;
    once(event: 'drain', listener: () => void): unknown;
}

export function writeWithBackpressure(
    source: PausableSource,
    destination: BackpressureDestination,
    chunk: unknown,
): void {
    if (destination.write(chunk)) return;
    source.pause();
    destination.once('drain', () => {
        if (!destination.destroyed) source.resume();
    });
}
