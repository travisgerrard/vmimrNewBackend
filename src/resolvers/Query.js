const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');

const Query = {
  learnings: forwardTo('db'),
  me(parent, args, ctx, info) {
    // check if there is a current user ID
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId }
      },
      info
    );
  },

  users(parent, args, ctx, info) {
    // 0. Check if logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }
    // 1. Check if user has permission to query all users
    //hasPermission(ctx.request.user, ["ADMIN", "PERMISSIONUPDATE"]);

    // 2. if they do have permission, query all users
    return ctx.db.query.users({}, info);
  }

  // learnings(parent, args, ctx, info) {
  //   return ctx.db.query.learnings({}, info);
  // }
};

module.exports = Query;
