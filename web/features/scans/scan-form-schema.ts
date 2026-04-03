import { z } from "zod";

export const scanFormSchema = z.object({
  project_id: z.string().min(1, "Project is required"),
  scan_type: z.enum(["SAST", "DAST", "SCA"], {
    message: "Scan type is required",
  }),
  target_id: z.string().min(1, "Target is required"),
  scan_profile: z.enum(["passive", "standard", "aggressive"]),
  label: z.string().optional(),
  environment: z.string().optional(),
});

export type ScanFormValues = z.infer<typeof scanFormSchema>;
