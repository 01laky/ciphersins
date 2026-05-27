export interface ColorPreference {
	color?: boolean;
	noColor?: boolean;
}

export function shouldUseColor(preference: ColorPreference = {}): boolean {
	if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== "") {
		return false;
	}

	if (preference.noColor) {
		return false;
	}

	if (preference.color === true) {
		return true;
	}

	if (preference.color === false) {
		return false;
	}

	if (process.env.CI === "true") {
		return false;
	}

	return process.stdout.isTTY === true;
}

const RESET = "\x1b[0m";

export const ANSI = {
	reset: RESET,
	bold: "\x1b[1m",
	critical: "\x1b[31m",
	high: "\x1b[91m",
	medium: "\x1b[33m",
	low: "\x1b[36m",
	dim: "\x1b[2m",
	cyan: "\x1b[36m",
} as const;

export function colorize(
	text: string,
	color: string,
	enabled: boolean,
): string {
	return enabled ? `${color}${text}${RESET}` : text;
}
