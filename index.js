import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());


// ======================================
// MongoDB
// ======================================

const client = new MongoClient(process.env.MONGODB_URI);

let db;

async function connectDB() {
  try {
    await client.connect();

    db = client.db(process.env.DB_NAME);

    console.log("MongoDB connected");
  } catch (error) {
    console.log("MongoDB connection failed");
  }
}


// ======================================
// JWT FUNCTIONS
// ======================================

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}


function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Token is required"
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid token"
    });
  }
}


function checkRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: "You do not have permission"
      });
    }

    next();
  };
}


// ======================================
// TEST ROUTE
// ======================================

app.get("/", (req, res) => {
  res.json({
    message: "HireLoop backend is running"
  });
});


// ======================================
// AUTH
// ======================================


// Register

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      role
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required"
      });
    }

    const userExists = await db
      .collection("users")
      .findOne({
        email
      });

    if (userExists) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const user = {
      name,
      email,
      password: hashedPassword,

      role: role === "recruiter"
        ? "recruiter"
        : "seeker",

      avatar: "",
      headline: "",
      bio: "",
      skills: [],
      resumeUrl: "",

      createdAt: new Date()
    };

    const result = await db
      .collection("users")
      .insertOne(user);

    user._id = result.insertedId;

    const token = createToken(user);

    delete user.password;

    res.status(201).json({
      message: "Registration successful",
      token,
      user
    });

  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});


// Login

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const user = await db
      .collection("users")
      .findOne({
        email
      });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = createToken(user);

    delete user.password;

    res.json({
      message: "Login successful",
      token,
      user
    });

  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});


// Get current user

app.get(
  "/api/auth/me",
  verifyToken,
  async (req, res) => {
    try {
      const user = await db
        .collection("users")
        .findOne(
          {
            _id: new ObjectId(req.user.id)
          },
          {
            projection: {
              password: 0
            }
          }
        );

      if (!user) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      res.json(user);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// USER PROFILE
// ======================================


// Get profile

app.get(
  "/api/users/profile",
  verifyToken,
  async (req, res) => {
    try {
      const user = await db
        .collection("users")
        .findOne(
          {
            _id: new ObjectId(req.user.id)
          },
          {
            projection: {
              password: 0
            }
          }
        );

      res.json(user);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Update profile

app.patch(
  "/api/users/profile",
  verifyToken,
  async (req, res) => {
    try {
      const {
        name,
        avatar,
        headline,
        bio,
        skills,
        resumeUrl
      } = req.body;

      await db
        .collection("users")
        .updateOne(
          {
            _id: new ObjectId(req.user.id)
          },
          {
            $set: {
              name,
              avatar,
              headline,
              bio,
              skills,
              resumeUrl,
              updatedAt: new Date()
            }
          }
        );

      res.json({
        message: "Profile updated successfully"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// COMPANY
// ======================================


// Create company

app.post(
  "/api/companies",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const {
        name,
        industry,
        location,
        website,
        description
      } = req.body;

      if (!name || !industry || !location) {
        return res.status(400).json({
          message:
            "Name, industry and location are required"
        });
      }

      const company = {
        recruiterId: new ObjectId(req.user.id),

        name,
        industry,
        location,

        website: website || "",
        description: description || "",

        status: "pending",

        createdAt: new Date()
      };

      const result = await db
        .collection("companies")
        .insertOne(company);

      res.status(201).json({
        message: "Company created",
        companyId: result.insertedId
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Get approved companies

app.get("/api/companies", async (req, res) => {
  try {
    const companies = await db
      .collection("companies")
      .find({
        status: "approved"
      })
      .sort({
        createdAt: -1
      })
      .toArray();

    res.json(companies);

  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});


// Get my company

app.get(
  "/api/companies/my",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const company = await db
        .collection("companies")
        .findOne({
          recruiterId:
            new ObjectId(req.user.id)
        });

      res.json(company);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// JOBS
// ======================================


// Create job

app.post(
  "/api/jobs",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
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

      const company = await db
        .collection("companies")
        .findOne({
          recruiterId:
            new ObjectId(req.user.id),

          status: "approved"
        });

      if (!company) {
        return res.status(400).json({
          message:
            "You need an approved company first"
        });
      }

      const job = {
        recruiterId:
          new ObjectId(req.user.id),

        companyId:
          company._id,

        title,
        category,
        type,
        location,

        salaryMin: salaryMin || 0,
        salaryMax: salaryMax || 0,

        description:
          description || "",

        requirements:
          requirements || "",

        deadline:
          deadline || "",

        status: "active",

        createdAt: new Date()
      };

      const result = await db
        .collection("jobs")
        .insertOne(job);

      res.status(201).json({
        message: "Job created successfully",
        jobId: result.insertedId
      });

    } catch (error) {
      console.log(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Get all jobs

app.get("/api/jobs", async (req, res) => {
  try {
    const {
      search,
      category,
      type,
      location
    } = req.query;

    const query = {
      status: "active"
    };

    if (search) {
      query.title = {
        $regex: search,
        $options: "i"
      };
    }

    if (category) {
      query.category = category;
    }

    if (type) {
      query.type = type;
    }

    if (location) {
      query.location = {
        $regex: location,
        $options: "i"
      };
    }

    const jobs = await db
      .collection("jobs")
      .find(query)
      .sort({
        createdAt: -1
      })
      .toArray();

    res.json(jobs);

  } catch (error) {
    res.status(500).json({
      message: "Server error"
    });
  }
});


// Get single job

app.get(
  "/api/jobs/:id",
  async (req, res) => {
    try {
      const job = await db
        .collection("jobs")
        .findOne({
          _id: new ObjectId(
            req.params.id
          )
        });

      if (!job) {
        return res.status(404).json({
          message: "Job not found"
        });
      }

      res.json(job);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Get recruiter jobs

app.get(
  "/api/jobs/my",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const jobs = await db
        .collection("jobs")
        .find({
          recruiterId:
            new ObjectId(req.user.id)
        })
        .sort({
          createdAt: -1
        })
        .toArray();

      res.json(jobs);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Update job

app.patch(
  "/api/jobs/:id",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
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

      const result = await db
        .collection("jobs")
        .updateOne(
          {
            _id:
              new ObjectId(
                req.params.id
              ),

            recruiterId:
              new ObjectId(
                req.user.id
              )
          },

          {
            $set: {
              title,
              category,
              type,
              location,
              salaryMin,
              salaryMax,
              description,
              requirements,
              deadline,
              updatedAt: new Date()
            }
          }
        );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          message: "Job not found"
        });
      }

      res.json({
        message: "Job updated successfully"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Delete job

app.delete(
  "/api/jobs/:id",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const result = await db
        .collection("jobs")
        .deleteOne({
          _id:
            new ObjectId(
              req.params.id
            ),

          recruiterId:
            new ObjectId(
              req.user.id
            )
        });

      if (result.deletedCount === 0) {
        return res.status(404).json({
          message: "Job not found"
        });
      }

      res.json({
        message: "Job deleted successfully"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// SAVE JOB
// ======================================


// Save job

app.post(
  "/api/saved-jobs/:jobId",
  verifyToken,
  checkRole("seeker"),
  async (req, res) => {
    try {
      const jobId =
        new ObjectId(
          req.params.jobId
        );

      const alreadySaved =
        await db
          .collection("savedJobs")
          .findOne({
            userId:
              new ObjectId(
                req.user.id
              ),

            jobId
          });

      if (alreadySaved) {
        return res.status(400).json({
          message: "Job already saved"
        });
      }

      await db
        .collection("savedJobs")
        .insertOne({
          userId:
            new ObjectId(
              req.user.id
            ),

          jobId,

          createdAt:
            new Date()
        });

      res.json({
        message: "Job saved successfully"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Get saved jobs

app.get(
  "/api/saved-jobs",
  verifyToken,
  checkRole("seeker"),
  async (req, res) => {
    try {
      const savedJobs =
        await db
          .collection("savedJobs")
          .aggregate([
            {
              $match: {
                userId:
                  new ObjectId(
                    req.user.id
                  )
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

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Remove saved job

app.delete(
  "/api/saved-jobs/:jobId",
  verifyToken,
  checkRole("seeker"),
  async (req, res) => {
    try {
      await db
        .collection("savedJobs")
        .deleteOne({
          userId:
            new ObjectId(
              req.user.id
            ),

          jobId:
            new ObjectId(
              req.params.jobId
            )
        });

      res.json({
        message:
          "Job removed from saved jobs"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// APPLICATION
// ======================================


// Apply for job

app.post(
  "/api/applications",
  verifyToken,
  checkRole("seeker"),
  async (req, res) => {
    try {
      const {
        jobId,
        resumeUrl,
        coverLetter
      } = req.body;

      if (!jobId) {
        return res.status(400).json({
          message: "Job ID is required"
        });
      }

      const job = await db
        .collection("jobs")
        .findOne({
          _id:
            new ObjectId(jobId),

          status: "active"
        });

      if (!job) {
        return res.status(404).json({
          message: "Job not found"
        });
      }

      const alreadyApplied =
        await db
          .collection("applications")
          .findOne({
            jobId:
              new ObjectId(jobId),

            seekerId:
              new ObjectId(
                req.user.id
              )
          });

      if (alreadyApplied) {
        return res.status(400).json({
          message:
            "You already applied for this job"
        });
      }

      const application = {
        jobId:
          new ObjectId(jobId),

        seekerId:
          new ObjectId(
            req.user.id
          ),

        companyId:
          job.companyId,

        resumeUrl:
          resumeUrl || "",

        coverLetter:
          coverLetter || "",

        status:
          "Applied",

        createdAt:
          new Date()
      };

      await db
        .collection("applications")
        .insertOne(application);

      res.status(201).json({
        message:
          "Application submitted successfully"
      });

    } catch (error) {
      console.log(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// My applications

app.get(
  "/api/applications/my",
  verifyToken,
  checkRole("seeker"),
  async (req, res) => {
    try {
      const applications =
        await db
          .collection("applications")
          .aggregate([
            {
              $match: {
                seekerId:
                  new ObjectId(
                    req.user.id
                  )
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

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Recruiter: see applicants

app.get(
  "/api/applications/job/:jobId",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const jobId =
        new ObjectId(
          req.params.jobId
        );

      const job = await db
        .collection("jobs")
        .findOne({
          _id: jobId,

          recruiterId:
            new ObjectId(
              req.user.id
            )
        });

      if (!job) {
        return res.status(404).json({
          message: "Job not found"
        });
      }

      const applications =
        await db
          .collection("applications")
          .aggregate([
            {
              $match: {
                jobId
              }
            },

            {
              $lookup: {
                from: "users",

                localField:
                  "seekerId",

                foreignField:
                  "_id",

                as: "seeker"
              }
            },

            {
              $unwind:
                "$seeker"
            },

            {
              $project: {
                resumeUrl: 1,
                coverLetter: 1,
                status: 1,
                createdAt: 1,

                seeker: {
                  name: 1,
                  email: 1,
                  avatar: 1,
                  headline: 1,
                  skills: 1
                }
              }
            }
          ])
          .toArray();

      res.json(applications);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Update application status

app.patch(
  "/api/applications/:id/status",
  verifyToken,
  checkRole("recruiter"),
  async (req, res) => {
    try {
      const {
        status
      } = req.body;

      const allowedStatus = [
        "Applied",
        "Reviewing",
        "Shortlisted",
        "Rejected",
        "Hired"
      ];

      if (!allowedStatus.includes(status)) {
        return res.status(400).json({
          message:
            "Invalid application status"
        });
      }

      const application =
        await db
          .collection("applications")
          .findOne({
            _id:
              new ObjectId(
                req.params.id
              )
          });

      if (!application) {
        return res.status(404).json({
          message:
            "Application not found"
        });
      }

      const job = await db
        .collection("jobs")
        .findOne({
          _id:
            application.jobId,

          recruiterId:
            new ObjectId(
              req.user.id
            )
        });

      if (!job) {
        return res.status(403).json({
          message:
            "You do not own this job"
        });
      }

      await db
        .collection("applications")
        .updateOne(
          {
            _id:
              application._id
          },

          {
            $set: {
              status,
              updatedAt:
                new Date()
            }
          }
        );

      res.json({
        message:
          "Application status updated"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// NOTIFICATIONS
// ======================================


// Get notifications

app.get(
  "/api/notifications",
  verifyToken,
  async (req, res) => {
    try {
      const notifications =
        await db
          .collection("notifications")
          .find({
            userId:
              new ObjectId(
                req.user.id
              )
          })
          .sort({
            createdAt: -1
          })
          .toArray();

      res.json(notifications);

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// Mark notification as read

app.patch(
  "/api/notifications/:id/read",
  verifyToken,
  async (req, res) => {
    try {
      await db
        .collection("notifications")
        .updateOne(
          {
            _id:
              new ObjectId(
                req.params.id
              ),

            userId:
              new ObjectId(
                req.user.id
              )
          },

          {
            $set: {
              read: true
            }
          }
        );

      res.json({
        message:
          "Notification marked as read"
      });

    } catch (error) {
      res.status(500).json({
        message: "Server error"
      });
    }
  }
);


// ======================================
// START SERVER
// ======================================

async function startServer() {
  await connectDB();

  app.listen(PORT, () => {
    console.log(
      `Server running on http://localhost:${PORT}`
    );
  });
}

startServer();