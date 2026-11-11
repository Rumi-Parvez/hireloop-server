import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true
  })
);

app.use(express.json());

// ==========================================
// MONGODB
// ==========================================

const client = new MongoClient(process.env.MONGODB_URI);

let db;

// সব MongoDB collection এক জায়গায়
const collections = {};

async function connectDB() {
  await client.connect();

  db = client.db(process.env.DB_NAME);

  collections.users = db.collection("users");
  collections.companies = db.collection("companies");
  collections.jobs = db.collection("jobs");
  collections.savedJobs = db.collection("savedJobs");
  collections.applications = db.collection("applications");
  collections.notifications = db.collection("notifications");

  console.log("MongoDB connected");
}

// ==========================================
// HELPER FUNCTIONS
// ==========================================

// Async route-এর error handle করবে
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Custom error
class AppError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.status = status;
  }
}

// MongoDB ObjectId validate করবে
function getId(id) {
  if (!ObjectId.isValid(id)) {
    throw new AppError("Invalid ID", 400);
  }

  return new ObjectId(id);
}

// Undefined value বাদ দেবে
function removeUndefined(data) {
  return Object.fromEntries(
    Object.entries(data).filter(([, value]) => value !== undefined)
  );
}

// Search-এর regex safe করবে
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ==========================================
// BETTER AUTH JWT
// ==========================================

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.BETTER_AUTH_URL}/api/auth/jwks`)
);

// Verify token এবং MongoDB থেকে user বের করবে
const verifyUser = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    throw new AppError("Authentication required", 401);
  }

  const token = authHeader.split(" ")[1];

  const { payload } = await jwtVerify(token, JWKS, {
    issuer: process.env.BETTER_AUTH_URL,
    audience: process.env.BETTER_AUTH_URL
  });

  if (!payload.sub) {
    throw new AppError("Invalid user token", 401);
  }

  // Better Auth user ID দিয়ে নিজের profile খুঁজবে
  let user = await collections.users.findOne({
    authUserId: payload.sub
  });

  // Profile না থাকলে নতুন seeker profile তৈরি করবে
  if (!user) {
    const newUser = {
      authUserId: payload.sub,
      name: payload.name || "",
      email: payload.email || "",
      role: "seeker",
      avatar: "",
      headline: "",
      bio: "",
      skills: [],
      resumeUrl: "",
      createdAt: new Date()
    };

    const result = await collections.users.insertOne(newUser);

    user = {
      ...newUser,
      _id: result.insertedId
    };
  }

  // Role MongoDB থেকে আসবে, JWT বা frontend থেকে নয়
  req.user = user;

  next();
});

// ==========================================
// ROLE CHECK
// ==========================================

function checkRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(new AppError("You do not have permission", 403));
    }

    next();
  };
}

// ==========================================
// TEST ROUTE
// ==========================================

app.get("/", (req, res) => {
  res.json({
    message: "HireLoop backend is running"
  });
});

// ==========================================
// USER PROFILE
// ==========================================

// Get profile
app.get(
  "/api/users/profile",
  verifyUser,
  asyncHandler(async (req, res) => {
    res.json(req.user);
  })
);

// Update profile
app.patch(
  "/api/users/profile",
  verifyUser,
  asyncHandler(async (req, res) => {
    const updateData = removeUndefined({
      name: req.body.name,
      avatar: req.body.avatar,
      headline: req.body.headline,
      bio: req.body.bio,
      skills: req.body.skills,
      resumeUrl: req.body.resumeUrl,
      updatedAt: new Date()
    });

    await collections.users.updateOne(
      { authUserId: req.user.authUserId },
      { $set: updateData }
    );

    res.json({
      message: "Profile updated successfully"
    });
  })
);

// ==========================================
// COMPANIES
// ==========================================

// Create company
app.post(
  "/api/companies",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const { name, industry, location, website, description } = req.body;

    if (!name || !industry || !location) {
      throw new AppError("Name, industry and location are required", 400);
    }

    const existingCompany = await collections.companies.findOne({
      recruiterId: req.user.authUserId
    });

    if (existingCompany) {
      throw new AppError("You already have a company", 400);
    }

    const company = {
      recruiterId: req.user.authUserId,
      name,
      industry,
      location,
      website: website || "",
      description: description || "",
      status: "pending",
      createdAt: new Date()
    };

    const result = await collections.companies.insertOne(company);

    res.status(201).json({
      message: "Company created successfully",
      companyId: result.insertedId
    });
  })
);

// Get all approved companies
app.get(
  "/api/companies",
  asyncHandler(async (req, res) => {
    const companies = await collections.companies
      .find({ status: "approved" })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(companies);
  })
);

// Get my company
app.get(
  "/api/companies/my",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const company = await collections.companies.findOne({
      recruiterId: req.user.authUserId
    });

    res.json(company);
  })
);

// Update my company
app.patch(
  "/api/companies/my",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const updateData = removeUndefined({
      name: req.body.name,
      industry: req.body.industry,
      location: req.body.location,
      website: req.body.website,
      description: req.body.description,
      updatedAt: new Date()
    });

    const result = await collections.companies.updateOne(
      { recruiterId: req.user.authUserId },
      { $set: updateData }
    );

    if (!result.matchedCount) {
      throw new AppError("Company not found", 404);
    }

    res.json({
      message: "Company updated successfully"
    });
  })
);

// ==========================================
// JOBS
// ==========================================

// Create job
app.post(
  "/api/jobs",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const {
      title,
      category,
      type,
      location,
      salaryMin,
      salaryMax,
      description,
      requirements,
      deadline
    } = req.body;

    if (!title || !category || !type || !location) {
      throw new AppError("Title, category, type and location are required", 400);
    }

    const company = await collections.companies.findOne({
      recruiterId: req.user.authUserId,
      status: "approved"
    });

    if (!company) {
      throw new AppError("You need an approved company first", 400);
    }

    const job = {
      recruiterId: req.user.authUserId,
      companyId: company._id,
      companyName: company.name,
      title,
      category,
      type,
      location,
      salaryMin: salaryMin || 0,
      salaryMax: salaryMax || 0,
      description: description || "",
      requirements: requirements || "",
      deadline: deadline || "",
      status: "active",
      createdAt: new Date()
    };

    const result = await collections.jobs.insertOne(job);

    res.status(201).json({
      message: "Job created successfully",
      jobId: result.insertedId
    });
  })
);

// Get all active jobs with filters
app.get(
  "/api/jobs",
  asyncHandler(async (req, res) => {
    const { search, category, type, location } = req.query;

    const query = { status: "active" };

    if (search) {
      query.title = {
        $regex: escapeRegex(search),
        $options: "i"
      };
    }

    if (category) query.category = category;
    if (type) query.type = type;

    if (location) {
      query.location = {
        $regex: escapeRegex(location),
        $options: "i"
      };
    }

    const jobs = await collections.jobs
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    res.json(jobs);
  })
);

// Get recruiter's jobs
// এই route-টি /:id route-এর আগে রাখতে হবে
app.get(
  "/api/jobs/my",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const jobs = await collections.jobs
      .find({ recruiterId: req.user.authUserId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(jobs);
  })
);

// Get single job
app.get(
  "/api/jobs/:id",
  asyncHandler(async (req, res) => {
    const job = await collections.jobs.findOne({
      _id: getId(req.params.id)
    });

    if (!job) {
      throw new AppError("Job not found", 404);
    }

    res.json(job);
  })
);

// Update job
app.patch(
  "/api/jobs/:id",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const updateData = removeUndefined({
      title: req.body.title,
      category: req.body.category,
      type: req.body.type,
      location: req.body.location,
      salaryMin: req.body.salaryMin,
      salaryMax: req.body.salaryMax,
      description: req.body.description,
      requirements: req.body.requirements,
      deadline: req.body.deadline,
      updatedAt: new Date()
    });

    const result = await collections.jobs.updateOne(
      {
        _id: getId(req.params.id),
        recruiterId: req.user.authUserId
      },
      { $set: updateData }
    );

    if (!result.matchedCount) {
      throw new AppError("Job not found", 404);
    }

    res.json({
      message: "Job updated successfully"
    });
  })
);

// Delete job
app.delete(
  "/api/jobs/:id",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const jobId = getId(req.params.id);

    const result = await collections.jobs.deleteOne({
      _id: jobId,
      recruiterId: req.user.authUserId
    });

    if (!result.deletedCount) {
      throw new AppError("Job not found", 404);
    }

    await collections.savedJobs.deleteMany({ jobId });

    res.json({
      message: "Job deleted successfully"
    });
  })
);

// ==========================================
// SAVED JOBS
// ==========================================

// Save job
app.post(
  "/api/saved-jobs/:jobId",
  verifyUser,
  checkRole("seeker"),
  asyncHandler(async (req, res) => {
    const jobId = getId(req.params.jobId);

    const job = await collections.jobs.findOne({
      _id: jobId,
      status: "active"
    });

    if (!job) {
      throw new AppError("Job not found", 404);
    }

    const alreadySaved = await collections.savedJobs.findOne({
      userId: req.user.authUserId,
      jobId
    });

    if (alreadySaved) {
      throw new AppError("Job already saved", 400);
    }

    await collections.savedJobs.insertOne({
      userId: req.user.authUserId,
      jobId,
      createdAt: new Date()
    });

    res.status(201).json({
      message: "Job saved successfully"
    });
  })
);

// Get saved jobs
app.get(
  "/api/saved-jobs",
  verifyUser,
  checkRole("seeker"),
  asyncHandler(async (req, res) => {
    const savedJobs = await collections.savedJobs
      .aggregate([
        {
          $match: {
            userId: req.user.authUserId
          }
        },
        {
          $lookup: {
            from: "jobs",
            localField: "jobId",
            foreignField: "_id",
            as: "job"
          }
        },
        {
          $unwind: "$job"
        }
      ])
      .toArray();

    res.json(savedJobs);
  })
);

// Remove saved job
app.delete(
  "/api/saved-jobs/:jobId",
  verifyUser,
  checkRole("seeker"),
  asyncHandler(async (req, res) => {
    await collections.savedJobs.deleteOne({
      userId: req.user.authUserId,
      jobId: getId(req.params.jobId)
    });

    res.json({
      message: "Job removed from saved jobs"
    });
  })
);

// ==========================================
// APPLICATIONS
// ==========================================

// Apply for job
app.post(
  "/api/applications",
  verifyUser,
  checkRole("seeker"),
  asyncHandler(async (req, res) => {
    const { jobId, resumeUrl, coverLetter } = req.body;

    if (!jobId) {
      throw new AppError("Job ID is required", 400);
    }

    const id = getId(jobId);

    const job = await collections.jobs.findOne({
      _id: id,
      status: "active"
    });

    if (!job) {
      throw new AppError("Job not found", 404);
    }

    const alreadyApplied = await collections.applications.findOne({
      jobId: id,
      seekerId: req.user.authUserId
    });

    if (alreadyApplied) {
      throw new AppError("You already applied for this job", 400);
    }

    const application = {
      jobId: id,
      seekerId: req.user.authUserId,
      seekerName: req.user.name || "",
      seekerEmail: req.user.email || "",
      companyId: job.companyId,
      resumeUrl: resumeUrl || "",
      coverLetter: coverLetter || "",
      status: "Applied",
      createdAt: new Date()
    };

    await collections.applications.insertOne(application);

    // Recruiter notification
    await collections.notifications.insertOne({
      userId: job.recruiterId,
      type: "application",
      message: `${req.user.name || "A candidate"} applied for your job: ${job.title}`,
      read: false,
      createdAt: new Date()
    });

    res.status(201).json({
      message: "Application submitted successfully"
    });
  })
);

// Get my applications
app.get(
  "/api/applications/my",
  verifyUser,
  checkRole("seeker"),
  asyncHandler(async (req, res) => {
    const applications = await collections.applications
      .aggregate([
        {
          $match: {
            seekerId: req.user.authUserId
          }
        },
        {
          $lookup: {
            from: "jobs",
            localField: "jobId",
            foreignField: "_id",
            as: "job"
          }
        },
        {
          $unwind: "$job"
        }
      ])
      .toArray();

    res.json(applications);
  })
);

// Recruiter: get applicants for a job
app.get(
  "/api/applications/job/:jobId",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const jobId = getId(req.params.jobId);

    const job = await collections.jobs.findOne({
      _id: jobId,
      recruiterId: req.user.authUserId
    });

    if (!job) {
      throw new AppError("Job not found", 404);
    }

    const applications = await collections.applications
      .find({ jobId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(applications);
  })
);

// Update application status
app.patch(
  "/api/applications/:id/status",
  verifyUser,
  checkRole("recruiter"),
  asyncHandler(async (req, res) => {
    const { status } = req.body;

    const allowedStatus = [
      "Applied",
      "Reviewing",
      "Shortlisted",
      "Rejected",
      "Hired"
    ];

    if (!allowedStatus.includes(status)) {
      throw new AppError("Invalid application status", 400);
    }

    const application = await collections.applications.findOne({
      _id: getId(req.params.id)
    });

    if (!application) {
      throw new AppError("Application not found", 404);
    }

    const job = await collections.jobs.findOne({
      _id: application.jobId,
      recruiterId: req.user.authUserId
    });

    if (!job) {
      throw new AppError("You do not own this job", 403);
    }

    await collections.applications.updateOne(
      { _id: application._id },
      {
        $set: {
          status,
          updatedAt: new Date()
        }
      }
    );

    // Seeker notification
    await collections.notifications.insertOne({
      userId: application.seekerId,
      type: "application-status",
      message: `Your application for ${job.title} is now ${status}`,
      read: false,
      createdAt: new Date()
    });

    res.json({
      message: "Application status updated"
    });
  })
);

// ==========================================
// NOTIFICATIONS
// ==========================================

// Get notifications
app.get(
  "/api/notifications",
  verifyUser,
  asyncHandler(async (req, res) => {
    const notifications = await collections.notifications
      .find({ userId: req.user.authUserId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(notifications);
  })
);

// Mark all notifications as read
app.patch(
  "/api/notifications/read-all",
  verifyUser,
  asyncHandler(async (req, res) => {
    await collections.notifications.updateMany(
      {
        userId: req.user.authUserId,
        read: false
      },
      {
        $set: { read: true }
      }
    );

    res.json({
      message: "All notifications marked as read"
    });
  })
);

// Mark one notification as read
app.patch(
  "/api/notifications/:id/read",
  verifyUser,
  asyncHandler(async (req, res) => {
    await collections.notifications.updateOne(
      {
        _id: getId(req.params.id),
        userId: req.user.authUserId
      },
      {
        $set: { read: true }
      }
    );

    res.json({
      message: "Notification marked as read"
    });
  })
);

// ==========================================
// ADMIN
// ==========================================

// Get pending companies
app.get(
  "/api/admin/companies",
  verifyUser,
  checkRole("admin"),
  asyncHandler(async (req, res) => {
    const companies = await collections.companies
      .find({ status: "pending" })
      .sort({ createdAt: -1 })
      .toArray();

    res.json(companies);
  })
);

// Approve or reject company
app.patch(
  "/api/admin/companies/:id/status",
  verifyUser,
  checkRole("admin"),
  asyncHandler(async (req, res) => {
    const { status } = req.body;

    if (!["approved", "rejected"].includes(status)) {
      throw new AppError("Invalid company status", 400);
    }

    const companyId = getId(req.params.id);

    const company = await collections.companies.findOne({
      _id: companyId
    });

    if (!company) {
      throw new AppError("Company not found", 404);
    }

    await collections.companies.updateOne(
      { _id: companyId },
      {
        $set: {
          status,
          updatedAt: new Date()
        }
      }
    );

    // Recruiter notification
    await collections.notifications.insertOne({
      userId: company.recruiterId,
      type: "company-status",
      message: `Your company "${company.name}" was ${status}`,
      read: false,
      createdAt: new Date()
    });

    res.json({
      message: `Company ${status} successfully`
    });
  })
);

// Get admin statistics
app.get(
  "/api/admin/stats",
  verifyUser,
  checkRole("admin"),
  asyncHandler(async (req, res) => {
    const users = await collections.users.countDocuments();
    const companies = await collections.companies.countDocuments();
    const jobs = await collections.jobs.countDocuments();
    const applications = await collections.applications.countDocuments();

    res.json({
      users,
      companies,
      jobs,
      applications
    });
  })
);

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    message: "Route not found"
  });
});

app.use((error, req, res, next) => {
  console.error(error);

  res.status(error.status || 500).json({
    message: error.status ? error.message : "Server error"
  });
});

// ==========================================
// START SERVER
// ==========================================

async function startServer() {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

startServer();