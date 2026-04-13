import { z } from "zod";

// We keep numeric form fields as strings inside the form (<input> returns
// strings), then coerce in the submit handler. Avoiding z.transform keeps
// the zodResolver Input/Output type identical, which react-hook-form needs.
export const targetFormSchema = z.object({
  project_id: z.string().min(1, "Project is required"),
  target_type: z.enum(["web_app", "api", "graphql"], {
    message: "Target type is required",
  }),
  base_url: z
    .string()
    .min(1, "Base URL is required")
    .refine((v) => {
      try {
        const u = new URL(v);
        return u.protocol === "http:" || u.protocol === "https:";
      } catch {
        return false;
      }
    }, "Must be a valid http(s) URL"),
  label: z.string().optional(),
  environment: z.string().optional(),
  notes: z.string().max(2000, "Notes too long").optional(),
  allowed_domains: z.string().optional(), // comma-separated in the form
  max_rps: z
    .string()
    .optional()
    .refine(
      (v) => {
        if (v === undefined || v === "") return true;
        const n = parseInt(v, 10);
        return !isNaN(n) && n > 0 && n <= 500;
      },
      { message: "Must be an integer between 1 and 500" },
    ),
  auth_config_id: z.string().optional(),
});

export type TargetFormValues = z.infer<typeof targetFormSchema>;
