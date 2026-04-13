import { z } from "zod";

// Backend validates lowercase scan types. "full" runs SAST + DAST together.
// The DB CHECK constraint allows only sast, dast, full (not sca).
//
// Input selection: dast/full require a target; sast can use either a target
// (legacy git path) or an uploaded source_artifact_id.
export const scanFormSchema = z
  .object({
    project_id: z.string().min(1, "Project is required"),
    scan_type: z.enum(["sast", "dast", "full"], {
      message: "Scan type is required",
    }),
    target_id: z.string().optional(),
    source_artifact_id: z.string().optional(),
    scan_profile: z.enum(["passive", "standard", "aggressive"]),
    label: z.string().optional(),
    environment: z.string().optional(),
  })
  .refine(
    (v) => {
      if (v.scan_type === "dast" || v.scan_type === "full") {
        return !!v.target_id;
      }
      // sast: require either
      return !!v.target_id || !!v.source_artifact_id;
    },
    {
      message: "Select a target or source artifact",
      path: ["target_id"],
    },
  );

export type ScanFormValues = z.infer<typeof scanFormSchema>;
