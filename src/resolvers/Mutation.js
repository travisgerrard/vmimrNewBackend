const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');
const stripe = require('../stripe');
const { forwardTo } = require('prisma-binding');

const mutations = {
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ['USER'] }
        }
      },
      info
    );
    // create JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // set the jwt as a cookie on the response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // finally return the user
    return user;
  },

  async signin(parent, { email, password }, ctx, info) {
    // 1. Check if there is a user with that email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`Now such user fround for email ${email}`);
    }
    // 2. Check if password correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error(`Invalid password`);
    }
    // 3. Generate JTW token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // 4. Set cookie with the token
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 5. Return the user
    return user;
  },

  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'Goodbye!' };
  },
  async requestReset(parent, args, ctx, info) {
    // 1. Check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if (!user) {
      throw new Error(`Now such user fround for email ${args.email}`);
    }
    // 2. Set a reset token and epxiry on that user
    const randomBytesPromiseified = promisify(randomBytes);
    const resetToken = (await randomBytesPromiseified(20)).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    });

    // 3. Email them that reset token
    const mailRes = await transport.sendMail({
      from: 'travisgerrard@gmail.com',
      to: user.email,
      subject: 'Your Password Reset',
      html: makeANiceEmail(
        `Your password reset token is here! \n\n <a href="${
          process.env.FRONTEND_URL
        }/reset?resetToken=${resetToken}">Click here to Reset</a>`
      )
    });

    // 4. Return the message
    return { message: 'Thanks' };
  },
  async resetPassword(parent, args, ctx, info) {
    // 1. check is passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error(`Passwords don't match`);
    }
    // 2. check if its a legit reset token
    // 3. Check if it's expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    });
    if (!user) {
      throw new Error(`Token is either invalid or expired`);
    }
    // 4. Hash their new password
    const password = await bcrypt.hash(args.password, 10);
    // 5. Save the new password to the user and remove old resetToken fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    // 6. Generate JWT
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    // 7. Set the JWT cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 8. Return the new user
    return updatedUser;
  },

  async createCard(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that');
    }

    const usersThatAreTagged = args.taggedUser.map(user => {
      return { id: user };
    });

    const card = await ctx.db.mutation.createPresentation(
      {
        data: {
          ...args,
          createdBy: {
            connect: {
              id: ctx.request.userId
            }
          },
          taggedUser: {
            connect: usersThatAreTagged
          },
          tags: {
            set: args.tags
          },
          presentationType: 'Pearl',
          myCreatedAt: new Date()
        }
      },
      info
    );

    console.log(card);
    return card;
  },

  async createPresentation(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that');
    }

    const usersThatAreTagged = args.taggedUser.map(user => {
      return { id: user };
    });

    const presentation = await ctx.db.mutation.createPresentation(
      {
        data: {
          ...args,
          createdBy: {
            connect: {
              id: ctx.request.userId
            }
          },
          taggedUser: {
            connect: usersThatAreTagged
          },
          tags: {
            set: args.tags
          },
          ddx: {
            set: args.ddx
          }
        }
      },
      info
    );

    return presentation;
  },

  async updatePresentation(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that');
    }

    const updates = { ...args };
    delete updates.id;

    const usersThatAreTagged = args.taggedUser.map(user => {
      return { id: user };
    });

    const presentation = await ctx.db.mutation.updatePresentation(
      {
        data: {
          ...updates,
          createdBy: {
            connect: {
              id: args.createdBy
            }
          },
          taggedUser: {
            connect: usersThatAreTagged
          },
          tags: {
            set: args.tags
          },
          ddx: {
            set: args.ddx
          }
        },
        where: {
          id: args.id
        }
      },
      info
    );

    return presentation;
  },

  deletePresentation(parent, args, ctx, info) {
    const where = { id: args.id };

    return ctx.db.mutation.deletePresentation({ where }, info);
  },

  async batchLoadPresentation(parent, args, ctx, info) {
    console.log(args);

    const presentation = await ctx.db.mutation.createPresentation(
      {
        data: {
          ...args,
          createdBy: {
            connect: {
              username: args.createdBy
            }
          },
          tags: {
            set: args.tags
          },
          ddx: {
            set: args.ddx
          }
        }
      },
      info
    );

    return presentation;
  },

  async batchLoadLearning(parent, args, ctx, info) {
    const taggedUserNew = args.taggedUser.map(taggedUser => {
      return { id: taggedUser };
    });

    // console.log(taggedUserNew);

    const presentation = await ctx.db.mutation.createPresentation(
      {
        data: {
          ...args,
          createdBy: {
            connect: {
              username: args.createdBy
            }
          },
          tags: {
            set: args.tags
          },
          taggedUser: {
            connect: taggedUserNew
          }
        }
      },
      info
    );

    return presentation;
  },

  async likePresentation(parent, args, ctx, info) {
    // console.log(args);

    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that');
    }

    const presentation = await ctx.db.query.presentation({
      where: {
        id: args.id
      }
    });

    // console.log(presentation);

    if (!presentation.likes) {
      const updatedPresentation = await ctx.db.mutation.updatePresentation({
        where: { id: args.id },
        data: {
          likes: {
            connect: [{ id: ctx.request.userId }]
          }
        },
        info
      });

      return updatedPresentation;
    }

    if (presentation.likes.contains(args.likes)) {
      const updatedPresentation = await ctx.db.mutation.updatePresentation({
        where: { id: args.id },
        data: {
          likes: presentation.likes.filter(function(likes) {
            return likes !== args.likes;
          })
        },
        info
      });
      return updatedPresentation;
    } else {
      const updatedPresentation = await ctx.db.mutation.updatePresentation({
        where: { id: args.id },
        data: {
          likes: [...presentation.likes, args.likes]
        }
      });
      return updatedPresentation;
    }
  },

  async deleteAllPresentations(parent, args, ctx, info) {
    const presentationIds = await ctx.db.query.presentations({}, info);
    const idArray = presentationIds.map(presentation => {
      return presentation.id;
    });
    console.log(idArray);

    await ctx.db.mutation.deleteManyPresentations({
      where: {
        id_in: idArray
      }
    });
  }
};

module.exports = mutations;
