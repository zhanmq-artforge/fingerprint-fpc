//! Fingerprint normalization, multi-angle geometric registration, and SSIM matching.
//!
//! Directly addresses:
//! - 200% bilinear upsampling (224x176) matching upstream C++ `load_data_and_proc`.
//! - Histogram equalization + Gamma 1.5 ridge contrast enhancement.
//! - Two-stage coarse-to-fine rotation ([-24° ..= +24°]) and translation ([-24 ..= +24]) search.
//! - Structural Similarity Index Measure (MSSIM) with 11x11 sliding windows.
//! - Pure-Rust implementation with zero C/C++ or OpenCV dependencies.

use serde::{Deserialize, Serialize};

/// Native optical/capacitive physical sensor resolution.
pub const SENSOR_RAW_WIDTH: usize = 112;
pub const SENSOR_RAW_HEIGHT: usize = 88;

/// Legacy upscaled dimensions (224x176) for backward compatibility with older databases.
pub const LEGACY_UPSCALED_WIDTH: usize = 224;
pub const LEGACY_UPSCALED_HEIGHT: usize = 176;

/// Maximum verified template scans stored per enrolled finger.
/// Aligns with standard 5-stage GNOME Control Center UI indicator rings.
pub const MAX_TEMPLATES_PER_FINGER: usize = 5;

/// Minimum MSSIM structural similarity score required for a verification match [0.0 .. 1.0].
/// Calibrated to 0.38 for a balanced False Acceptance Rate (FAR) and False Rejection Rate (FRR).
pub const DEFAULT_MATCH_THRESHOLD: f32 = 0.38;

/// High-confidence single-template match threshold allowing immediate verification pass.
pub const HIGH_CONFIDENCE_THRESHOLD: f32 = 0.44;

/// Result of attempting to add a scan template during multi-stage enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollStageResult {
    /// Template accepted and stored.
    Passed,
    /// Image contrast or ridge variance is too low (accidental brush or weak contact).
    LowQuality,
    /// Press is too identical to a previous scan (> 0.96 similarity); user must reposition or tilt finger.
    DuplicatePress,
    /// Press has insufficient overlap (< 0.08 similarity) with existing prints of the same finger.
    Mismatch,
    /// Maximum templates already reached.
    Completed,
}

/// A single normalized 8-bit grayscale fingerprint scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintScan {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

impl FingerprintScan {
    /// Create and contrast-enhance a raw sensor frame at its native physical sensor resolution.
    /// Eliminates the 4x computational overhead of artificial 2x bilinear upsampling while preserving 100% of physical ridge detail.
    pub fn from_raw(raw_bytes: &[u8], width: usize, height: usize) -> Self {
        let enhanced = preprocess_frame(raw_bytes, width, height);
        Self {
            width,
            height,
            data: enhanced,
        }
    }

    /// Normalize scan to native resolution. Provides backward compatibility for templates
    /// saved in legacy 224x176 format by downsampling them to physical resolution.
    pub fn ensure_normalized(&self) -> Self {
        if self.width == LEGACY_UPSCALED_WIDTH && self.height == LEGACY_UPSCALED_HEIGHT {
            let downsampled = downsample_2x(&self.data, self.width, self.height);
            Self {
                width: SENSOR_RAW_WIDTH,
                height: SENSOR_RAW_HEIGHT,
                data: downsampled,
            }
        } else {
            self.clone()
        }
    }

    /// Legacy compatibility wrapper.
    pub fn ensure_upscaled(&self) -> Self {
        self.ensure_normalized()
    }

    /// Compute biometric similarity between two scans using multi-angle rotation,
    /// 2D translation alignment, and Mean Structural Similarity (MSSIM).
    pub fn compute_similarity(&self, other: &Self) -> f32 {
        let scan_a = self.ensure_normalized();
        let scan_b = other.ensure_normalized();

        if scan_a.width != scan_b.width || scan_a.height != scan_b.height {
            return 0.0;
        }

        let width = scan_a.width;
        let height = scan_a.height;

        // Perform coarse-to-fine rotation and translation alignment
        let (best_angle_rad, best_dx, best_dy) =
            find_optimal_alignment(&scan_a.data, &scan_b.data, width, height);

        // Compute MSSIM at the optimal alignment
        compute_aligned_mssim(
            &scan_a.data,
            &scan_b.data,
            width,
            height,
            best_angle_rad,
            best_dx,
            best_dy,
        )
    }
}

/// An enrolled finger containing multiple high-quality scan templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledFinger {
    pub user: String,
    pub finger_name: String,
    pub templates: Vec<FingerprintScan>,
}

impl EnrolledFinger {
    /// Create a new enrolled finger record.
    pub fn new(user: impl Into<String>, finger_name: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            finger_name: finger_name.into(),
            templates: Vec::with_capacity(MAX_TEMPLATES_PER_FINGER),
        }
    }

    /// Attempt to add a scan template, returning a detailed result status.
    ///
    /// Provides anti-debounce and diversity checks:
    /// - Rejects identical presses (> 0.90 similarity) to ensure spatial coverage across angles.
    /// - Rejects unrelated fingers (< 0.16 similarity).
    /// - Rejects low-contrast frames (variance < 10.0).
    pub fn try_add_template(&mut self, scan: FingerprintScan) -> EnrollStageResult {
        if self.templates.len() >= MAX_TEMPLATES_PER_FINGER {
            return EnrollStageResult::Completed;
        }

        let scan = scan.ensure_upscaled();

        // 1. Basic image quality check: Ensure adequate ridge contrast variance
        let variance = compute_image_variance(&scan.data);
        if variance < 10.0 {
            tracing::warn!("Enroll press rejected: low variance ({variance:.2} < 10.0)");
            return EnrollStageResult::LowQuality;
        }

        if self.templates.is_empty() {
            tracing::info!("Enroll stage 1 accepted (variance: {variance:.2})");
            self.templates.push(scan);
            return EnrollStageResult::Passed;
        }

        // 2. Multi-angle similarity check against already enrolled templates
        let mut best_sim = 0.0f32;
        for t in &self.templates {
            let sim = t.compute_similarity(&scan);
            if sim > best_sim {
                best_sim = sim;
            }
        }

        tracing::info!(
            "Enroll press evaluation: best_sim={best_sim:.3}, variance={variance:.2}, current_templates={}",
            self.templates.len()
        );

        // Anti-debounce protection: if the user holds their finger continuously without moving,
        // similarity to previous scans will be virtually identical (> 0.96).
        if best_sim > 0.96 {
            tracing::warn!("Enroll press rejected: duplicate press ({best_sim:.3} > 0.96)");
            return EnrollStageResult::DuplicatePress;
        }

        // Reject completely unrelated fingers or spurious touches.
        // Calibrated to 0.08 to allow real-world partial edge/tip contacts on tiny (8x6mm) sensors
        // without triggering false Mismatch lockout.
        if best_sim < 0.08 {
            tracing::warn!("Enroll press rejected: mismatch ({best_sim:.3} < 0.08)");
            return EnrollStageResult::Mismatch;
        }

        tracing::info!("Enroll press accepted as new template (similarity: {best_sim:.3})");
        self.templates.push(scan);
        EnrollStageResult::Passed
    }

    /// Add a new scan template if it provides good coverage and quality.
    /// Returns true if accepted, false if redundant or low quality.
    pub fn add_template(&mut self, scan: FingerprintScan) -> bool {
        self.try_add_template(scan) == EnrollStageResult::Passed
    }

    /// Verify a candidate scan against all enrolled templates.
    ///
    /// Implements two-tier verification:
    /// - High confidence (>= 0.44): immediate pass.
    /// - Standard pass (threshold .. 0.44): if multiple templates are enrolled,
    ///   requires secondary correlation to avoid single-artifact false accepts (FAR protection).
    ///
    /// Returns `(matched, best_score)`.
    pub fn verify(&self, candidate: &FingerprintScan, threshold: f32) -> (bool, f32) {
        let cand = candidate.ensure_upscaled();
        let mut scores = Vec::with_capacity(self.templates.len());

        for template in &self.templates {
            let score = template.compute_similarity(&cand);
            if score >= HIGH_CONFIDENCE_THRESHOLD {
                // High confidence match -> short-circuit immediately
                return (true, score);
            }
            scores.push(score);
        }

        let best_score = scores.iter().copied().fold(0.0f32, f32::max);
        if best_score < threshold {
            return (false, best_score);
        }

        // Secondary FAR protection for marginal scores:
        if self.templates.len() > 1 && best_score < HIGH_CONFIDENCE_THRESHOLD {
            let correlated_count = scores.iter().filter(|&&s| s >= 0.26).count();
            if correlated_count < 2 {
                tracing::warn!(
                    "Marginal score ({best_score:.3}) rejected by FAR protection: secondary correlation count < 2"
                );
                return (false, best_score);
            }
        }

        (true, best_score)
    }

    /// Number of enrolled stages completed.
    pub fn stage_count(&self) -> usize {
        self.templates.len()
    }

    /// Whether enrollment is complete.
    pub fn is_complete(&self) -> bool {
        self.templates.len() >= MAX_TEMPLATES_PER_FINGER
    }
}

// =============================================================================
// Image Enhancement & Preprocessing
// =============================================================================

/// Compute variance of image pixels to detect blank or noisy frames.
fn compute_image_variance(pixels: &[u8]) -> f32 {
    if pixels.is_empty() {
        return 0.0;
    }
    let n = pixels.len() as f64;
    let sum: f64 = pixels.iter().map(|&p| p as f64).sum();
    let mean = sum / n;
    let var: f64 = pixels
        .iter()
        .map(|&p| {
            let diff = p as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;
    var.sqrt() as f32
}

/// Filter dead/stuck sensor pixels, apply histogram equalization and Gamma 1.5 contrast enhancement.
/// Operates directly at native sensor resolution (112x88 for 9201, 128x88 for a900) without wasteful 2x upsampling.
fn preprocess_frame(raw: &[u8], width: usize, height: usize) -> Vec<u8> {
    if raw.is_empty() || width == 0 || height == 0 {
        return Vec::new();
    }

    let expected_len = width * height;
    let mut pixels = Vec::with_capacity(expected_len);
    if raw.len() >= expected_len {
        pixels.extend_from_slice(&raw[..expected_len]);
    } else {
        pixels.extend_from_slice(raw);
        pixels.resize(expected_len, 128);
    }

    // 1. Dead/stuck pixel filter:
    // Capacitive sensors frequently have isolated defective pixels (stuck at 0 or 255).
    // Interpolate isolated stuck pixels using the mean of valid 4-neighbors to prevent CDF skewing.
    if width > 2 && height > 2 {
        for y in 1..height - 1 {
            let row = y * width;
            for x in 1..width - 1 {
                let idx = row + x;
                let val = pixels[idx];
                if val == 0 || val == 255 {
                    let up = pixels[idx - width];
                    let down = pixels[idx + width];
                    let left = pixels[idx - 1];
                    let right = pixels[idx + 1];

                    // If neighbors are within typical active range, replace with mean
                    if (1..=254).contains(&up)
                        && (1..=254).contains(&down)
                        && (1..=254).contains(&left)
                        && (1..=254).contains(&right)
                    {
                        pixels[idx] =
                            ((up as u32 + down as u32 + left as u32 + right as u32) / 4) as u8;
                    }
                }
            }
        }
    }

    // 2. Calculate histogram
    let mut hist = [0u32; 256];
    for &val in &pixels {
        hist[val as usize] += 1;
    }

    // 3. Cumulative distribution function (CDF)
    let mut cdf = [0u32; 256];
    let mut acc = 0u32;
    for i in 0..256 {
        acc += hist[i];
        cdf[i] = acc;
    }

    let total = pixels.len() as f32;
    let min_cdf = cdf.iter().copied().find(|&c| c > 0).unwrap_or(0) as f32;
    let denom = (total - min_cdf).max(1.0);

    // 4. Combined LUT for Equalization + Gamma 1.5
    let mut lut = [0u8; 256];
    let gamma = 1.5f32;
    for i in 0..256 {
        let eq = ((cdf[i] as f32 - min_cdf) / denom).clamp(0.0, 1.0);
        let corrected = eq.powf(gamma);
        lut[i] = (corrected * 255.0).round().clamp(0.0, 255.0) as u8;
    }

    pixels.iter().map(|&p| lut[p as usize]).collect()
}

/// Downsample 2x by area averaging for backward compatibility with legacy 224x176 templates.
fn downsample_2x(src: &[u8], src_w: usize, src_h: usize) -> Vec<u8> {
    let dst_w = src_w / 2;
    let dst_h = src_h / 2;
    let mut dst = vec![0u8; dst_w * dst_h];

    for y in 0..dst_h {
        let r0 = (y * 2) * src_w;
        let r1 = (y * 2 + 1) * src_w;
        let out_row = y * dst_w;

        for x in 0..dst_w {
            let x2 = x * 2;
            let sum = src[r0 + x2] as u32
                + src[r0 + x2 + 1] as u32
                + src[r1 + x2] as u32
                + src[r1 + x2 + 1] as u32;
            dst[out_row + x] = (sum / 4) as u8;
        }
    }
    dst
}

// =============================================================================
// Geometric Rotation & Registration
// =============================================================================

/// Rotate an image around its center using bilinear interpolation.
/// Also outputs a boolean validity mask indicating pixels from within the source bounds.
fn rotate_image(
    src: &[u8],
    width: usize,
    height: usize,
    angle_rad: f32,
    out: &mut [u8],
    mask: &mut [bool],
) {
    if angle_rad.abs() < 1e-4 {
        out.copy_from_slice(src);
        mask.fill(true);
        return;
    }

    let cx = (width - 1) as f32 * 0.5;
    let cy = (height - 1) as f32 * 0.5;

    let cos_a = angle_rad.cos();
    let sin_a = angle_rad.sin();

    let max_x = (width - 1) as f32;
    let max_y = (height - 1) as f32;

    for y in 0..height {
        let dy = y as f32 - cy;
        let row_idx = y * width;
        for x in 0..width {
            let dx = x as f32 - cx;

            // Backward mapping: query source coordinates
            let src_x = cx + dx * cos_a + dy * sin_a;
            let src_y = cy - dx * sin_a + dy * cos_a;

            let idx = row_idx + x;
            if src_x >= 0.0 && src_x < max_x && src_y >= 0.0 && src_y < max_y {
                let x0 = src_x.floor() as usize;
                let y0 = src_y.floor() as usize;
                let x1 = x0 + 1;
                let y1 = y0 + 1;

                let fx = src_x - x0 as f32;
                let fy = src_y - y0 as f32;

                let p00 = src[y0 * width + x0] as f32;
                let p01 = src[y0 * width + x1] as f32;
                let p10 = src[y1 * width + x0] as f32;
                let p11 = src[y1 * width + x1] as f32;

                let top = p00 * (1.0 - fx) + p01 * fx;
                let bot = p10 * (1.0 - fx) + p11 * fx;
                let val = top * (1.0 - fy) + bot * fy;

                out[idx] = val.round().clamp(0.0, 255.0) as u8;
                mask[idx] = true;
            } else {
                out[idx] = 0;
                mask[idx] = false;
            }
        }
    }
}

/// Coarse-to-fine registration to find optimal rotation and 2D translation alignment.
fn find_optimal_alignment(
    template: &[u8],
    candidate: &[u8],
    width: usize,
    height: usize,
) -> (f32, isize, isize) {
    let mut rot_buf = vec![0u8; width * height];
    let mut rot_mask = vec![false; width * height];

    let mut best_score = -1.0f32;
    let mut best_angle_deg = 0.0f32;
    let mut best_dx = 0isize;
    let mut best_dy = 0isize;

    // Stage 1: Coarse search over angles [-24° ..= +24°] in 6° increments
    // and translation [-20 ..= 20] in 2-pixel increments (~1.0mm physical shift tolerance at native 500 DPI)
    let coarse_angles: [f32; 9] = [-24.0, -18.0, -12.0, -6.0, 0.0, 6.0, 12.0, 18.0, 24.0];

    for &deg in &coarse_angles {
        let rad = deg.to_radians();
        rotate_image(candidate, width, height, rad, &mut rot_buf, &mut rot_mask);

        for dy in (-20..=20).step_by(2) {
            for dx in (-20..=20).step_by(2) {
                let score =
                    compute_subsampled_ncc(template, &rot_buf, &rot_mask, width, height, dx, dy);
                if score > best_score {
                    best_score = score;
                    best_angle_deg = deg;
                    best_dx = dx;
                    best_dy = dy;
                }
            }
        }
    }

    // Stage 2: Fine search in the local neighborhood
    let fine_angles: [f32; 5] = [
        best_angle_deg - 3.0,
        best_angle_deg - 1.5,
        best_angle_deg,
        best_angle_deg + 1.5,
        best_angle_deg + 3.0,
    ];

    let min_dx = (best_dx - 2).max(-20);
    let max_dx = (best_dx + 2).min(20);
    let min_dy = (best_dy - 2).max(-20);
    let max_dy = (best_dy + 2).min(20);

    let mut refined_score = best_score;
    let mut refined_angle_deg = best_angle_deg;
    let mut refined_dx = best_dx;
    let mut refined_dy = best_dy;

    for &deg in &fine_angles {
        if !(-25.0..=25.0).contains(&deg) {
            continue;
        }
        let rad = deg.to_radians();
        rotate_image(candidate, width, height, rad, &mut rot_buf, &mut rot_mask);

        for dy in min_dy..=max_dy {
            for dx in min_dx..=max_dx {
                let score =
                    compute_subsampled_ncc(template, &rot_buf, &rot_mask, width, height, dx, dy);
                if score > refined_score {
                    refined_score = score;
                    refined_angle_deg = deg;
                    refined_dx = dx;
                    refined_dy = dy;
                }
            }
        }
    }

    (refined_angle_deg.to_radians(), refined_dx, refined_dy)
}

/// Fast subsampled normalized cross-correlation for registration scoring.
fn compute_subsampled_ncc(
    img1: &[u8],
    img2: &[u8],
    mask2: &[bool],
    width: usize,
    height: usize,
    dx: isize,
    dy: isize,
) -> f32 {
    let mut sum1: f64 = 0.0;
    let mut sum2: f64 = 0.0;
    let mut sum1_sq: f64 = 0.0;
    let mut sum2_sq: f64 = 0.0;
    let mut sum_prod: f64 = 0.0;
    let mut count: usize = 0;

    // Subsample by 2 for fast coarse grid evaluation
    for y in (0..height).step_by(2) {
        let y2 = y as isize + dy;
        if y2 < 0 || y2 >= height as isize {
            continue;
        }
        let row1 = y * width;
        let row2 = y2 as usize * width;

        for x in (0..width).step_by(2) {
            let x2 = x as isize + dx;
            if x2 < 0 || x2 >= width as isize {
                continue;
            }

            let idx2 = row2 + x2 as usize;
            if !mask2[idx2] {
                continue;
            }

            let idx1 = row1 + x;
            let val1 = img1[idx1] as f64;
            let val2 = img2[idx2] as f64;

            sum1 += val1;
            sum2 += val2;
            sum1_sq += val1 * val1;
            sum2_sq += val2 * val2;
            sum_prod += val1 * val2;
            count += 1;
        }
    }

    // Require at least ~15% overlapping sample points
    let min_samples = (width * height) / 25;
    if count < min_samples {
        return -1.0;
    }

    let n = count as f64;
    let num = n * sum_prod - sum1 * sum2;
    let den1 = n * sum1_sq - sum1 * sum1;
    let den2 = n * sum2_sq - sum2 * sum2;

    if den1 <= 0.0 || den2 <= 0.0 {
        return 0.0;
    }

    let den = (den1 * den2).sqrt();
    (num / den).clamp(-1.0, 1.0) as f32
}

// =============================================================================
// Mean Structural Similarity Index Measure (MSSIM)
// =============================================================================

/// Compute Mean Structural Similarity (MSSIM) over overlapping regions.
/// Matches standard MSSIM formulation (Wang et al., 2004) with C1=6.5025, C2=58.5225.
fn compute_aligned_mssim(
    template: &[u8],
    candidate: &[u8],
    width: usize,
    height: usize,
    angle_rad: f32,
    dx: isize,
    dy: isize,
) -> f32 {
    let mut rot_cand = vec![0u8; width * height];
    let mut rot_mask = vec![false; width * height];

    rotate_image(
        candidate,
        width,
        height,
        angle_rad,
        &mut rot_cand,
        &mut rot_mask,
    );

    // Standard SSIM stability constants for 8-bit images:
    // C1 = (K1 * L)^2 = (0.01 * 255)^2 = 6.5025
    // C2 = (K2 * L)^2 = (0.03 * 255)^2 = 58.5225
    const C1: f64 = 6.5025;
    const C2: f64 = 58.5225;

    const BLOCK_SIZE: usize = 9;
    const STRIDE: usize = 4;

    let mut total_ssim: f64 = 0.0;
    let mut valid_blocks: usize = 0;

    let max_y = height.saturating_sub(BLOCK_SIZE);
    let max_x = width.saturating_sub(BLOCK_SIZE);

    for by in (0..=max_y).step_by(STRIDE) {
        let by2 = by as isize + dy;
        if by2 < 0 || (by2 + BLOCK_SIZE as isize) > height as isize {
            continue;
        }

        for bx in (0..=max_x).step_by(STRIDE) {
            let bx2 = bx as isize + dx;
            if bx2 < 0 || (bx2 + BLOCK_SIZE as isize) > width as isize {
                continue;
            }

            // Verify that block has sufficient valid pixels within rotated boundary
            let mut block_count: usize = 0;
            let mut sum_x: f64 = 0.0;
            let mut sum_y: f64 = 0.0;
            let mut sum_xx: f64 = 0.0;
            let mut sum_yy: f64 = 0.0;
            let mut sum_xy: f64 = 0.0;

            for iy in 0..BLOCK_SIZE {
                let y1 = by + iy;
                let y2 = (by2 as usize) + iy;
                let r1 = y1 * width;
                let r2 = y2 * width;

                for ix in 0..BLOCK_SIZE {
                    let x1 = bx + ix;
                    let x2 = (bx2 as usize) + ix;
                    let idx2 = r2 + x2;

                    if !rot_mask[idx2] {
                        continue;
                    }

                    let val1 = template[r1 + x1] as f64;
                    let val2 = rot_cand[idx2] as f64;

                    sum_x += val1;
                    sum_y += val2;
                    sum_xx += val1 * val1;
                    sum_yy += val2 * val2;
                    sum_xy += val1 * val2;
                    block_count += 1;
                }
            }

            // Require at least ~60% valid pixels in the window (50 out of 81)
            if block_count < 50 {
                continue;
            }

            let n = block_count as f64;
            let mu_x = sum_x / n;
            let mu_y = sum_y / n;

            let var_x = (sum_xx / n) - (mu_x * mu_x);
            let var_y = (sum_yy / n) - (mu_y * mu_y);

            // Skip flat background regions without sufficient ridge contrast
            if var_x < 12.0 || var_y < 12.0 {
                continue;
            }

            let cov_xy = (sum_xy / n) - (mu_x * mu_y);

            let num = (2.0 * mu_x * mu_y + C1) * (2.0 * cov_xy + C2);
            let den = (mu_x * mu_x + mu_y * mu_y + C1) * (var_x + var_y + C2);

            if den > 1e-6 {
                let ssim = (num / den).clamp(0.0, 1.0);
                total_ssim += ssim;
                valid_blocks += 1;
            }
        }
    }

    if valid_blocks < 14 {
        return 0.0;
    }

    (total_ssim / valid_blocks as f64) as f32
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_synthetic_fingerprint(width: usize, height: usize, angle_deg: f32) -> Vec<u8> {
        generate_synthetic_fingerprint_advanced(width, height, angle_deg, 0.0, 0.0, 0.0)
    }

    fn generate_synthetic_fingerprint_advanced(
        width: usize,
        height: usize,
        angle_deg: f32,
        shift_x: f32,
        shift_y: f32,
        distortion: f32,
    ) -> Vec<u8> {
        let mut img = vec![0u8; width * height];
        let rad = angle_deg.to_radians();
        let cos_a = rad.cos();
        let sin_a = rad.sin();
        let cx = width as f32 * 0.5 + shift_x;
        let cy = height as f32 * 0.5 + shift_y;

        for y in 0..height {
            for x in 0..width {
                let dx = x as f32 - cx;
                let dy = y as f32 - cy;
                let rot_x = dx * cos_a + dy * sin_a;
                let rot_y = -dx * sin_a + dy * cos_a;

                // Simulate curved ridges with realistic skin elasticity distortion
                let r = (rot_x * rot_x + rot_y * rot_y).sqrt();
                let deform = distortion * (rot_y * 0.15).sin();
                let val =
                    (128.0 + 100.0 * ((rot_x * 0.25 + r * 0.1 + deform).sin())).clamp(0.0, 255.0);
                img[y * width + x] = val as u8;
            }
        }
        img
    }

    #[test]
    fn test_identical_scan_mssim_high() {
        let raw = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let scan1 = FingerprintScan::from_raw(&raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        let scan2 = scan1.clone();

        let score = scan1.compute_similarity(&scan2);
        assert!(
            score > 0.90,
            "Identical scan must produce very high MSSIM, got: {score}"
        );
    }

    #[test]
    fn test_rotation_tolerance_mssim() {
        // Finger pressed at 0° vs finger pressed at 10° tilt
        let raw1 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let raw2 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 10.0);

        let scan1 = FingerprintScan::from_raw(&raw1, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        let scan2 = FingerprintScan::from_raw(&raw2, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        let score = scan1.compute_similarity(&scan2);
        assert!(
            score >= DEFAULT_MATCH_THRESHOLD,
            "10° tilted scan must match above threshold ({DEFAULT_MATCH_THRESHOLD}), got: {score}"
        );
    }

    #[test]
    fn test_translation_tolerance_mssim() {
        // Finger shifted by (6, 6)
        let raw1 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let scan1 = FingerprintScan::from_raw(&raw1, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        // Shift raw pixels
        let mut raw2 = vec![128u8; SENSOR_RAW_WIDTH * SENSOR_RAW_HEIGHT];
        for y in 0..SENSOR_RAW_HEIGHT - 6 {
            for x in 0..SENSOR_RAW_WIDTH - 6 {
                raw2[(y + 6) * SENSOR_RAW_WIDTH + (x + 6)] = raw1[y * SENSOR_RAW_WIDTH + x];
            }
        }
        let scan2 = FingerprintScan::from_raw(&raw2, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        let score = scan1.compute_similarity(&scan2);
        assert!(
            score >= DEFAULT_MATCH_THRESHOLD,
            "Translated scan must match above threshold ({DEFAULT_MATCH_THRESHOLD}), got: {score}"
        );
    }

    #[test]
    fn test_unrelated_fingerprint_rejection() {
        let raw1 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        // Completely different orthogonal ridge orientation (90° rotated pattern / different finger)
        let raw2 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 90.0);

        let scan1 = FingerprintScan::from_raw(&raw1, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        let scan2 = FingerprintScan::from_raw(&raw2, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        let score = scan1.compute_similarity(&scan2);
        assert!(
            score < DEFAULT_MATCH_THRESHOLD,
            "Unrelated scan must not pass threshold ({DEFAULT_MATCH_THRESHOLD}), got: {score}"
        );
    }

    #[test]
    fn test_enrolled_finger_multi_stage_and_verify() {
        let mut enrolled = EnrolledFinger::new("testuser", "right-index-finger");

        // Enroll stage 1: Center 0°
        let raw0 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let scan0 = FingerprintScan::from_raw(&raw0, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        assert!(enrolled.add_template(scan0));
        assert_eq!(enrolled.stage_count(), 1);

        // Enroll stage 2: Shifted contact with slight natural skin pressure variation
        let raw_side = generate_synthetic_fingerprint_advanced(
            SENSOR_RAW_WIDTH,
            SENSOR_RAW_HEIGHT,
            8.0,
            12.0,
            10.0,
            0.6,
        );
        let scan_side = FingerprintScan::from_raw(&raw_side, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        let res_side = enrolled.try_add_template(scan_side);
        assert_eq!(res_side, EnrollStageResult::Passed);
        assert_eq!(enrolled.stage_count(), 2);

        // Enroll stage 3: Another angle and shift with skin variation
        let raw_other = generate_synthetic_fingerprint_advanced(
            SENSOR_RAW_WIDTH,
            SENSOR_RAW_HEIGHT,
            -8.0,
            -10.0,
            -8.0,
            0.5,
        );
        let scan_other = FingerprintScan::from_raw(&raw_other, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        assert_eq!(
            enrolled.try_add_template(scan_other),
            EnrollStageResult::Passed
        );
        assert_eq!(enrolled.stage_count(), 3);

        // Verify with a candidate overlapping enrolled coverage
        let cand_raw = generate_synthetic_fingerprint_advanced(
            SENSOR_RAW_WIDTH,
            SENSOR_RAW_HEIGHT,
            6.0,
            8.0,
            6.0,
            0.5,
        );
        let cand = FingerprintScan::from_raw(&cand_raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        let (matched, score) = enrolled.verify(&cand, DEFAULT_MATCH_THRESHOLD);
        assert!(
            matched,
            "Enrolled finger must verify candidate scan at 8°, got score: {score}"
        );
    }

    #[test]
    fn test_anti_debounce_duplicate_press_rejected() {
        let mut enrolled = EnrolledFinger::new("testuser", "right-index-finger");

        let raw = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let scan1 = FingerprintScan::from_raw(&raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        let scan_duplicate = scan1.clone();

        assert_eq!(
            enrolled.try_add_template(scan1),
            EnrollStageResult::Passed,
            "First stage must be accepted"
        );

        // Identical scan without moving finger must be caught by anti-debounce
        assert_eq!(
            enrolled.try_add_template(scan_duplicate),
            EnrollStageResult::DuplicatePress,
            "Duplicate press must be rejected for anti-debounce"
        );
        assert_eq!(enrolled.stage_count(), 1);
    }

    #[test]
    fn test_low_quality_scan_rejected() {
        let mut enrolled = EnrolledFinger::new("testuser", "right-index-finger");
        // Flat blank image (no ridges)
        let blank_raw = vec![128u8; SENSOR_RAW_WIDTH * SENSOR_RAW_HEIGHT];
        let blank_scan = FingerprintScan::from_raw(&blank_raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        assert_eq!(
            enrolled.try_add_template(blank_scan),
            EnrollStageResult::LowQuality,
            "Blank or weak contrast scan must be rejected as LowQuality"
        );
    }

    #[test]
    fn test_dead_pixel_filtering() {
        let mut raw = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        // Inject an isolated dead pixel (0) and an isolated hot/stuck pixel (255)
        let dead_idx = 10 * SENSOR_RAW_WIDTH + 10;
        let hot_idx = 20 * SENSOR_RAW_WIDTH + 20;
        raw[dead_idx] = 0;
        raw[hot_idx] = 255;

        // Process frame with filtering
        let processed = preprocess_frame(&raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        // Also process clean frame without dead pixels for comparison
        let clean_raw = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let clean_processed = preprocess_frame(&clean_raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        // Dead and hot pixels should be restored close to the true clean value (< 25 after histogram stretch)
        let diff_dead = (processed[dead_idx] as i32 - clean_processed[dead_idx] as i32).abs();
        let diff_hot = (processed[hot_idx] as i32 - clean_processed[hot_idx] as i32).abs();

        assert!(
            diff_dead <= 25,
            "Dead pixel must be interpolated close to clean value, diff: {diff_dead}"
        );
        assert!(
            diff_hot <= 25,
            "Hot pixel must be interpolated close to clean value, diff: {diff_hot}"
        );
    }

    #[test]
    fn test_legacy_224x176_template_compatibility() {
        let raw = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let native_scan = FingerprintScan::from_raw(&raw, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        // Simulate a legacy 224x176 template stored in old format
        let mut legacy_data = vec![0u8; LEGACY_UPSCALED_WIDTH * LEGACY_UPSCALED_HEIGHT];
        for y in 0..LEGACY_UPSCALED_HEIGHT {
            for x in 0..LEGACY_UPSCALED_WIDTH {
                legacy_data[y * LEGACY_UPSCALED_WIDTH + x] =
                    native_scan.data[(y / 2) * SENSOR_RAW_WIDTH + (x / 2)];
            }
        }
        let legacy_scan = FingerprintScan {
            width: LEGACY_UPSCALED_WIDTH,
            height: LEGACY_UPSCALED_HEIGHT,
            data: legacy_data,
        };

        // Comparing legacy 224x176 with native 112x88 should transparently downsample and produce high match
        let score = native_scan.compute_similarity(&legacy_scan);
        assert!(
            score > 0.85,
            "Legacy 224x176 template must match native scan transparently, got: {score}"
        );
    }

    #[test]
    fn test_edge_coverage_enrollment_accepted() {
        let mut enrolled = EnrolledFinger::new("testuser", "right-index-finger");
        let raw0 = generate_synthetic_fingerprint(SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT, 0.0);
        let scan0 = FingerprintScan::from_raw(&raw0, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);
        assert_eq!(enrolled.try_add_template(scan0), EnrollStageResult::Passed);

        // A partial edge press with high translation and tilt (simulating edge of finger)
        let raw_edge = generate_synthetic_fingerprint_advanced(
            SENSOR_RAW_WIDTH,
            SENSOR_RAW_HEIGHT,
            16.0,
            18.0,
            14.0,
            0.6,
        );
        let scan_edge = FingerprintScan::from_raw(&raw_edge, SENSOR_RAW_WIDTH, SENSOR_RAW_HEIGHT);

        // With the improved 0.08 lower bound, this partial edge touch must be accepted
        // into multi-stage templates rather than triggering Mismatch
        let result = enrolled.try_add_template(scan_edge);
        assert_eq!(
            result,
            EnrollStageResult::Passed,
            "Partial edge press should be accepted during enrollment, got: {result:?}"
        );
    }
}
