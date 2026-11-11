import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merges conditional class names and resolves Tailwind conflicts (shadcn convention). */
export const cn = (...inputs) => twMerge(clsx(inputs));
